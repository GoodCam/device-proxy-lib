use std::{
    collections::HashMap,
    error::Error,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
};

use futures::{
    channel::oneshot::{self, Receiver, Sender},
    ready, FutureExt,
};
use hyper::{
    body::{Body, Incoming},
    rt::{Read, Write},
    service::{HttpService, Service},
    Request, Response,
};
use hyper_util::server::conn::auto::{HttpServerConnExec, UpgradeableConnection};

/// Graceful shutdown helper.
///
/// Tasks can be registered here and signaled to shut down gracefully.
pub struct GracefulShutdown {
    context: Arc<Mutex<GracefulShutdownContext>>,
}

impl GracefulShutdown {
    /// Create a new graceful shutdown helper.
    pub fn new() -> Self {
        Self {
            context: Arc::new(Mutex::new(GracefulShutdownContext::new())),
        }
    }

    /// Register a new task.
    pub fn register_task(&self) -> ShutdownRegistration {
        let (start_shutdown_tx, start_shutdown_rx) = oneshot::channel();
        let (shutdown_finished_tx, shutdown_finished_rx) = oneshot::channel();

        let handle = TaskHandle {
            start_shutdown_tx,
            shutdown_finished_rx,
        };

        let id = self.context.lock().unwrap().register_task(handle);

        let registration = TaskRegistration {
            context: Arc::downgrade(&self.context),
            id,
        };

        let finish_shutdown = FinishShutdown {
            _registration: registration,
            shutdown_finished_tx,
        };

        ShutdownRegistration {
            start_shutdown_rx,
            finish_shutdown: Some(finish_shutdown),
        }
    }

    /// Signal all tasks to shut down gracefully and wait until they all get
    /// shut down.
    pub async fn shutdown(self) {
        let f = self.context.lock().unwrap().graceful_shutdown();

        std::mem::drop(self.context);

        f.await
    }
}

/// Graceful shutdown context.
struct GracefulShutdownContext {
    tasks: HashMap<u64, TaskHandle>,
    next_id: u64,
}

impl GracefulShutdownContext {
    /// Create a new context.
    fn new() -> Self {
        Self {
            tasks: HashMap::new(),
            next_id: 0,
        }
    }

    /// Register a new task and return its ID.
    fn register_task(&mut self, handle: TaskHandle) -> u64 {
        let id = self.next_id;

        self.next_id = self.next_id.wrapping_add(1);

        self.tasks.insert(id, handle);

        id
    }

    /// Remove a task with a given ID.
    fn remove_task(&mut self, id: u64) {
        self.tasks.remove(&id);
    }

    /// Signal all tasks to shut down gracefully and return a future that will
    /// resolve once all tasks get shut down.
    fn graceful_shutdown(&mut self) -> impl Future<Output = ()> {
        let finished = self
            .tasks
            .drain()
            .map(|(_, c)| c.shutdown())
            .collect::<Vec<_>>();

        async move {
            for f in finished {
                f.await;
            }
        }
    }
}

/// Task handle.
struct TaskHandle {
    start_shutdown_tx: Sender<()>,
    shutdown_finished_rx: Receiver<()>,
}

impl TaskHandle {
    /// Request graceful shutdown of the corresponding task and wait until the
    /// task shuts down itself.
    async fn shutdown(self) {
        // send the shutdown signal
        let _ = self.start_shutdown_tx.send(());

        // ... and wait until the task is terminated
        let _ = self.shutdown_finished_rx.await;
    }
}

/// Task registration.
///
/// The registration will automatically remove itself from the shutdown
/// context when dropped.
struct TaskRegistration {
    context: Weak<Mutex<GracefulShutdownContext>>,
    id: u64,
}

impl Drop for TaskRegistration {
    fn drop(&mut self) {
        if let Some(context) = self.context.upgrade() {
            context.lock().unwrap().remove_task(self.id);
        }
    }
}

/// Graceful shutdown event sender.
///
/// The task that is being shut down will use this sender to notify any
/// shutdown-awaiting task that the shutdown has finished.
pub struct FinishShutdown {
    _registration: TaskRegistration,
    shutdown_finished_tx: Sender<()>,
}

impl FinishShutdown {
    /// Finish the shutdown.
    pub fn finish(self) {
        let _ = self.shutdown_finished_tx.send(());
    }
}

/// Future that gets resolved if a graceful shutdown is requested.
pub struct ShutdownRegistration {
    start_shutdown_rx: Receiver<()>,
    finish_shutdown: Option<FinishShutdown>,
}

impl Future for ShutdownRegistration {
    type Output = FinishShutdown;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let _ = ready!(self.start_shutdown_rx.poll_unpin(cx));

        let res = self.finish_shutdown.take();

        Poll::Ready(res.unwrap())
    }
}

/// Helper trait.
pub trait UpgradeableConnectionExt<'a, I, S, E>
where
    S: HttpService<Incoming>,
{
    /// Create a connection with integrated shutdown handler.
    fn with_graceful_shutdown(
        self,
        shutdown: ShutdownRegistration,
    ) -> UpgradeableConnectionWithShutdown<'a, I, S, E>;
}

impl<'a, I, S, E> UpgradeableConnectionExt<'a, I, S, E> for UpgradeableConnection<'a, I, S, E>
where
    S: HttpService<Incoming>,
{
    fn with_graceful_shutdown(
        self,
        shutdown: ShutdownRegistration,
    ) -> UpgradeableConnectionWithShutdown<'a, I, S, E> {
        UpgradeableConnectionWithShutdown {
            connection: self,
            start_shutdown: Some(shutdown),
            finish_shutdown: None,
        }
    }
}

pin_project_lite::pin_project! {
    /// Connection with graceful shutdown handling.
    pub struct UpgradeableConnectionWithShutdown<'a, I, S, E>
    where
        S: HttpService<Incoming>,
    {
        #[pin]
        connection: UpgradeableConnection<'a, I, S, E>,
        start_shutdown: Option<ShutdownRegistration>,
        finish_shutdown: Option<FinishShutdown>,
    }
}

impl<'a, I, S, E, B> Future for UpgradeableConnectionWithShutdown<'a, I, S, E>
where
    S: Service<Request<Incoming>, Response = Response<B>>,
    S::Future: 'static,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
    B: Body + 'static,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
    I: Read + Write + Unpin + Send + 'static,
    E: HttpServerConnExec<S::Future, B>,
{
    type Output = Result<(), Box<dyn Error + Send + Sync>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        if let Some(s) = this.start_shutdown.as_mut() {
            if let Poll::Ready(f) = s.poll_unpin(cx) {
                let c = this.connection.as_mut();

                // initiate the connection shutdown
                c.graceful_shutdown();

                *this.start_shutdown = None;
                *this.finish_shutdown = Some(f);
            }
        }

        let res = ready!(this.connection.poll(cx));

        if let Some(f) = this.finish_shutdown.take() {
            f.finish();
        }

        // make sure that we drop the registration if shutdown hasn't been
        // requested yet
        *this.start_shutdown = None;

        Poll::Ready(res)
    }
}
