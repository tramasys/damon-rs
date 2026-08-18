use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

mod state;

use state::*;
pub(crate) use state::{ModelRegion, ModelSchemeStats, Mutation};

#[derive(Clone, Debug)]
pub(crate) struct Model {
    root: PathBuf,
    state: Arc<Mutex<State>>,
}

impl Model {
    pub(crate) fn new(available_operations: &str) -> Self {
        Self::with_operation_sets(available_operations, available_operations, true)
    }

    pub(crate) fn without_available_operations_file(available_operations: &str) -> Self {
        Self::with_operation_sets(available_operations, available_operations, false)
    }

    pub(crate) fn with_legacy_operation_sets(
        available_operations: &str,
        recognized_operations: &str,
    ) -> Self {
        Self::with_operation_sets(available_operations, recognized_operations, false)
    }

    fn with_operation_sets(
        available_operations: &str,
        recognized_operations: &str,
        expose_available_operations: bool,
    ) -> Self {
        static NEXT_MODEL: AtomicU64 = AtomicU64::new(0);
        let root = PathBuf::from(format!(
            "/__damon_rs_model/{}-{}",
            std::process::id(),
            NEXT_MODEL.fetch_add(1, Ordering::Relaxed)
        ));
        let state = Arc::new(Mutex::new(State::new(
            available_operations,
            recognized_operations,
            expose_available_operations,
        )));
        registry()
            .lock()
            .expect("test backend registry lock poisoned")
            .push((root.clone(), Arc::downgrade(&state)));
        Self { root, state }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn set_tried_regions(&self, regions: Vec<ModelRegion>) {
        lock(&self.state).tried_regions = regions;
    }

    pub(crate) fn set_scheme_stats(&self, stats: Vec<ModelSchemeStats>) {
        lock(&self.state).scheme_stats = stats;
    }

    pub(crate) fn set_effective_quota_bytes(&self, quotas: Vec<u64>) {
        lock(&self.state).effective_quota_bytes = quotas;
    }

    pub(crate) fn set_supported_scheme_filter_types(&self, types: &str) {
        lock(&self.state).supported_scheme_filter_types = types.as_bytes().to_vec();
    }

    pub(crate) fn set_supported_probe_filter_types(&self, types: &str) {
        lock(&self.state).supported_probe_filter_types = types.as_bytes().to_vec();
    }

    pub(crate) fn enable_current_damo_extensions(&self) {
        let mut state = lock(&self.state);
        state.expose_current_damo_extensions = true;
        state.supported_probe_filter_types = b"anon\nmemcg\npgidle_unset\n".to_vec();
    }

    pub(crate) fn disable_effective_quota(&self) {
        lock(&self.state).expose_effective_quota = false;
    }

    pub(crate) fn remove_tree(&self, path: impl AsRef<Path>) {
        lock(&self.state).remove_tree(path.as_ref());
    }

    pub(crate) fn set_file(&self, path: impl Into<PathBuf>, value: &[u8]) {
        let path = path.into();
        let mut state = lock(&self.state);
        if !state.nodes.contains_key(&path) {
            state.extension_files.insert(path.clone(), value.to_vec());
        }
        state.file(path, value);
    }

    pub(crate) fn value(&self, path: impl AsRef<Path>) -> Option<String> {
        match lock(&self.state).nodes.get(path.as_ref())? {
            Node::File(value) => Some(String::from_utf8_lossy(value).trim().to_owned()),
            Node::Directory => None,
        }
    }

    pub(crate) fn active_value(&self, path: impl AsRef<Path>) -> Option<String> {
        lock(&self.state)
            .active_files
            .as_ref()?
            .get(path.as_ref())
            .map(|value| String::from_utf8_lossy(value).trim().to_owned())
    }

    pub(crate) fn after_next_read(&self, path: impl Into<PathBuf>, mutations: Vec<Mutation>) {
        lock(&self.state).hooks.push(Hook {
            event: HookEvent::Read(path.into()),
            mutations,
        });
    }

    pub(crate) fn after_next_write(
        &self,
        path: impl Into<PathBuf>,
        value: impl Into<Vec<u8>>,
        mutations: Vec<Mutation>,
    ) {
        lock(&self.state).hooks.push(Hook {
            event: HookEvent::Write(path.into(), value.into()),
            mutations,
        });
    }

    pub(crate) fn fail_next_write(&self, path: impl Into<PathBuf>, raw_os_error: i32) {
        lock(&self.state).write_failures.push(WriteFailure {
            path: path.into(),
            raw_os_error,
        });
    }

    pub(crate) fn write_count(&self) -> usize {
        lock(&self.state).write_count
    }

    pub(crate) fn read_count(&self) -> usize {
        lock(&self.state).read_count
    }
}

type Registry = Vec<(PathBuf, Weak<Mutex<State>>)>;

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

fn lock(state: &Arc<Mutex<State>>) -> MutexGuard<'_, State> {
    state.lock().expect("test backend state lock poisoned")
}

fn listed_value_contains(values: &[u8], requested: &str) -> bool {
    std::str::from_utf8(values)
        .expect("modeled capability values are UTF-8")
        .lines()
        .map(str::trim)
        .any(|value| value == requested)
}

fn resolve(path: &Path) -> Option<(Arc<Mutex<State>>, PathBuf)> {
    let mut registry = registry()
        .lock()
        .expect("test backend registry lock poisoned");
    registry.retain(|(_, state)| state.strong_count() > 0);
    registry
        .iter()
        .filter_map(|(root, state)| {
            let relative = path.strip_prefix(root).ok()?.to_path_buf();
            Some((root.components().count(), state.upgrade()?, relative))
        })
        .max_by_key(|(depth, _, _)| *depth)
        .map(|(_, state, relative)| (state, relative))
}

fn not_found(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("modeled sysfs path {} does not exist", path.display()),
    )
}

pub(super) fn path_exists(path: &Path) -> Option<io::Result<bool>> {
    let (state, relative) = resolve(path)?;
    Some(Ok(lock(&state).nodes.contains_key(&relative)))
}

pub(super) fn path_is_dir(path: &Path) -> Option<io::Result<bool>> {
    let (state, relative) = resolve(path)?;
    Some(Ok(matches!(
        lock(&state).nodes.get(&relative),
        Some(Node::Directory)
    )))
}

pub(super) fn numeric_directories(path: &Path) -> Option<io::Result<Vec<(usize, PathBuf)>>> {
    let (state, relative) = resolve(path)?;
    let state = lock(&state);
    if !matches!(state.nodes.get(&relative), Some(Node::Directory)) {
        return Some(if state.nodes.contains_key(&relative) {
            Err(io::Error::from(io::ErrorKind::NotADirectory))
        } else {
            Ok(Vec::new())
        });
    }
    let mut numeric = state
        .nodes
        .iter()
        .filter_map(|(candidate, node)| {
            if !matches!(node, Node::Directory) || candidate.parent() != Some(&relative) {
                return None;
            }
            let index = candidate.file_name()?.to_str()?.parse::<usize>().ok()?;
            Some((index, path.join(index.to_string())))
        })
        .collect::<Vec<_>>();
    numeric.sort_unstable_by_key(|(index, _)| *index);
    Some(Ok(numeric))
}

pub(super) fn all_files_recursive(path: &Path) -> Option<io::Result<Vec<PathBuf>>> {
    let (state, relative) = resolve(path)?;
    let state = lock(&state);
    if !matches!(state.nodes.get(&relative), Some(Node::Directory)) {
        return Some(Err(not_found(&relative)));
    }
    Some(Ok(state
        .nodes
        .iter()
        .filter_map(|(candidate, node)| {
            if !matches!(node, Node::File(_)) || !candidate.starts_with(&relative) {
                return None;
            }
            Some(path.join(candidate.strip_prefix(&relative).ok()?))
        })
        .collect()))
}

pub(super) fn path_is_writable(path: &Path) -> Option<io::Result<bool>> {
    let (state, relative) = resolve(path)?;
    Some(match lock(&state).nodes.get(&relative) {
        Some(Node::File(_)) => Ok(true),
        Some(Node::Directory) => Err(io::Error::from(io::ErrorKind::IsADirectory)),
        None => Err(not_found(&relative)),
    })
}

pub(super) fn read(path: &Path) -> Option<io::Result<Vec<u8>>> {
    let (state, relative) = resolve(path)?;
    let mut state = lock(&state);
    let result = match state.nodes.get(&relative) {
        Some(Node::File(value)) => Ok(value.clone()),
        Some(Node::Directory) => Err(io::Error::from(io::ErrorKind::IsADirectory)),
        None => Err(not_found(&relative)),
    };
    state.read_count += 1;
    state.apply_hooks(&HookEvent::Read(relative));
    Some(result)
}

pub(super) fn write(path: &Path, value: &[u8]) -> Option<io::Result<()>> {
    let (state, relative) = resolve(path)?;
    let mut state = lock(&state);
    let result = state.write(&relative, value);
    if result.is_ok() {
        state.write_count += 1;
        state.apply_hooks(&HookEvent::Write(relative, value.to_vec()));
    }
    Some(result)
}
