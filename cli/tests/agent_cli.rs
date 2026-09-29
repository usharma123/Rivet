use serde_json::{json, Value};
use std::{fs, process::Command};

fn invoke(root: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rivet"))
        .args(args)
        .current_dir(root)
        .env("RIVET_HOME", root.join("home"))
        .env("RIVET_REGISTRY_URL", "http://127.0.0.1:1")
        .output()
        .unwrap()
}

fn error(root: &std::path::Path, args: &[&str], code: &str) -> Value {
    let output = invoke(root, args);
    assert!(!output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], code);
    value
}

#[test]
fn json_failures_include_parse_manifest_and_frozen_lock_errors() {
    let root = tempfile::tempdir().unwrap();
    error(
        root.path(),
        &["install", "--unknown", "--json"],
        "INVALID_ARGUMENTS",
    );
    error(root.path(), &["install", "--json"], "PROJECT_NOT_FOUND");
    fs::write(root.path().join("package.json"), "{broken").unwrap();
    error(root.path(), &["install", "--json"], "INVALID_MANIFEST");
    fs::write(root.path().join("package.json"), "{}").unwrap();
    error(root.path(), &["ci", "--json"], "LOCKFILE_STALE");
}

#[test]
fn edits_preserve_unrelated_npm_fields_and_plan_preserves_bytes() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("package.json");
    let original =
        "{\n  \"private\": true, \"scripts\": {\"test\": \"node test.js\"}, \"custom\": [1,2]\n}\n";
    fs::write(&path, original).unwrap();
    assert!(
        invoke(root.path(), &["add", "prettier@3.5.3", "--plan", "--json"])
            .status
            .success()
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
    let output = invoke(root.path(), &["add", "prettier@3.5.3", "--json"]);
    assert!(output.status.success(), "{:?}", output);
    let document: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(document["private"], true);
    assert_eq!(document["scripts"]["test"], "node test.js");
    assert_eq!(document["custom"], json!([1, 2]));
    assert_eq!(document["dependencies"]["prettier"], "3.5.3");
    assert!(!root.path().join("rivet.toml").exists());
    assert!(!root.path().join("rivet.lock").exists());
}

#[test]
fn init_existing_npm_project_creates_only_policy_and_does_not_replace_it() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("package.json"), "{\"name\":\"example\"}").unwrap();
    assert!(invoke(root.path(), &["init", "--json"]).status.success());
    let policy = root.path().join("rivet.toml");
    assert!(!fs::read_to_string(&policy).unwrap().contains("[package]"));
    fs::write(&policy, "[policy]\nrequire_provenance = true\n").unwrap();
    assert!(invoke(root.path(), &["init", "--json"]).status.success());
    assert!(fs::read_to_string(policy)
        .unwrap()
        .contains("require_provenance = true"));
}

#[test]
fn unsupported_semantics_are_not_silently_ignored() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("package.json");
    for document in [
        json!({"workspaces":["packages/*"]}),
        json!({"overrides":{"a":"1"}}),
        json!({"optionalDependencies":{"a":"1"}}),
    ] {
        fs::write(&path, document.to_string()).unwrap();
        error(root.path(), &["install", "--json"], "UNSUPPORTED_PROJECT");
    }
    fs::write(&path, json!({"dependencies":{"a":"file:../a"}}).to_string()).unwrap();
    error(
        root.path(),
        &["install", "--json"],
        "UNSUPPORTED_DEPENDENCY",
    );
    fs::write(&path, "{}").unwrap();
    fs::write(root.path().join("rivet.toml"), "[dependencies]\na = '1'\n").unwrap();
    error(root.path(), &["install", "--json"], "AMBIGUOUS_MANIFEST");
}

#[test]
fn concurrent_project_mutation_returns_retryable_error_and_lock_releases() {
    use std::os::fd::AsRawFd;
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("package.json"), "{}").unwrap();
    fs::create_dir(root.path().join(".rivet")).unwrap();
    let lock = fs::File::create(root.path().join(".rivet/project.lock")).unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let value = error(root.path(), &["add", "prettier", "--json"], "PROJECT_BUSY");
    assert_eq!(value["error"]["retryable"], true);
    drop(lock);
    assert!(invoke(root.path(), &["add", "prettier", "--json"])
        .status
        .success());
}

#[test]
fn failed_network_install_does_not_save_dependency_edit() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("package.json");
    fs::write(&path, "{}").unwrap();
    error(
        root.path(),
        &["install", "prettier", "--json"],
        "REGISTRY_UNAVAILABLE",
    );
    assert_eq!(fs::read_to_string(path).unwrap(), "{}");
    assert!(!root.path().join("rivet.lock").exists());
    assert!(!root.path().join("node_modules").exists());
}
