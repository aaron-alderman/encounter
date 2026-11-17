use crate::{Result, appdev_host_process::{ServiceTool, Supervisor, interruption}, fail, process::{Meter, Programme}};
use serde_json::json;
use std::{collections::BTreeSet, time::Duration};

pub(super) const HOOK_NAME: &str = "sourcery-nginx-reload";

#[derive(Clone, Copy, Debug, PartialEq)]
enum Action { Validate, Reload }

fn deploy(mut apply: impl FnMut(Action) -> Result<()>) -> Result<()> {
    let policy = Programme::admit(&[include_str!("hosted_tls_deploy.encounter").to_owned()], "hostedTls.deploy",
        &BTreeSet::new(), &mut Meter::new(10_000))?;
    let decision = |state| policy.run("hostedTls.deploy", json!(state), &mut Meter::new(10_000));
    if decision("renewed")? != "validate-nginx" { return Err(fail("Expected hosted nginx validation")); }
    apply(Action::Validate)?;
    if interruption().is_some() { return Err(fail("Hosted nginx deployment interrupted")); }
    if decision("validated")? != "reload-nginx" { return Err(fail("Expected an admitted hosted nginx reload")); }
    apply(Action::Reload)
}

pub(crate) fn run() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 { return Err(fail("Hosted nginx renewal deployment requires root")); }
    let mut supervisor = Supervisor::new();
    deploy(|action| match action {
        Action::Validate => supervisor.run_until("Hosted nginx configuration validation",
            ServiceTool::Nginx.command()?.args(["-t", "-q"]), Some(Duration::from_secs(15))),
        Action::Reload => crate::systemd_user_service::reload_nginx(Duration::from_secs(30), false),
    })
}

#[cfg(test)]
#[test]
fn hosted_reload_requires_a_successful_validation() -> Result<()> {
    let mut calls = Vec::new();
    assert!(deploy(|action| { calls.push(action); Err(fail("fixture validation failed")) }).is_err());
    assert_eq!(calls, [Action::Validate]);
    calls.clear();
    deploy(|action| { calls.push(action); Ok(()) })?;
    assert_eq!(calls, [Action::Validate, Action::Reload]);
    Ok(())
}
