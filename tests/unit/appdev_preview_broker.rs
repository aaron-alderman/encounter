use super::{Path, Result, Value, json};

#[test]
fn synthetic_sign_in_preserves_only_the_declared_return_route() -> Result<()> {
    use crate::command::Evaluator;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../applications/appdev-projects");
    let workflow = Evaluator::load(&root, "release/workflow.rel")?;
    let route = |path, query| workflow.run("previewBroker.route", json!({
        "localHost":true, "method":"GET", "path":path, "query":query, "account":null
    }));
    let identity = "/identity-management/identity";
    let state = "state_1";
    assert_eq!(route(identity, json!({"state":state}))?,
        json!({"kind":"gateway","target":format!("{identity}?state={state}"),"account":null}));
    assert_eq!(route(identity, json!({"state":state,"returned":"1","fixture":"member"}))?,
        json!({"kind":"gateway","target":format!("{identity}?state={state}&returned=1"),"account":"member"}));
    assert_eq!(route(identity, json!({"state":state,"returned":"1","extra":"member"}))?["status"], 400);
    let login = route("/identity/login", json!({"return":format!("{identity}?returned=1&state={state}")}))?;
    assert!(login["body"].as_str().unwrap().contains("returned=1&amp;state=state_1&amp;fixture=member"));
    assert_eq!(route("/identity/login", json!({"return":"//other.example.test/"}))?["status"], 400);
    let response = |status, location| workflow.run("previewBroker.gatewayResponse", json!({
        "preview":31962,"status":status,"location":location
    }));
    assert_eq!(response("303", json!(format!("http://127.0.0.1:31962/identity-management/finish?code={}", "a".repeat(48))))?["status"],
        "303 See Other");
    assert!(response("303", json!(format!("http://127.0.0.1:31963/identity-management/finish?code={}", "a".repeat(48)))).is_err());
    assert_eq!(response("403", Value::Null)?["status"], "403 Forbidden");
    assert!(response("403", json!("/identity/login")).is_err());
    assert!(response("303", Value::Null).is_err());
    assert!(response("200", Value::Null).is_err());
    assert!(workflow.run("previewBroker.configure", json!({"steward":"steward@outside.example"})).is_err());
    Ok(())
}
