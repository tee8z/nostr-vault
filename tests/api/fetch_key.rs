use crate::helpers::{delete_row, spawn_app};
use nostr_vault::authentication::StoredKey;
use reqwest::StatusCode;
use serde_json::json;

#[tokio::test]
async fn fetch_key_success() {
    let test_app = spawn_app().await;
    let client = reqwest::Client::new();
    let nip_05_id = "the_name_is_smith_bob_smith@test.com";
    let private_key_hash = "$PBKDF2$i=100000,l=256,s=0Bu5lWu4s66/iottrlUGdckjf5nwnpB05jwp4yDh8NU=$AESGM$OrScsD+hHGaRaPbc$XMXVVbjt3JV+QsNb7ZWRc8uNod2YzJL0lSvW1FOiY38ywOu7IEChKs/IqEQ7knhZAmRGYqoB4dhAbdOTwVhYIeQsuf1+f+9ARPEjtURsDg==";
    let pin = 374859;
    let form_data = json!({"nip_05_id":nip_05_id,"pin":pin, "private_key_hash":private_key_hash});
    let response_upload = client
        .post(&format!("{}/upload_key", &test_app.address))
        .json(&form_data)
        .send()
        .await
        .expect("Failed to execute request.");
    assert!(response_upload.status().is_success());

    let req_data = json!({"nip_05_id":nip_05_id, "pin":pin});
    let response_fetch = client
        .post(&format!("{}/fetch_key", &test_app.address))
        .json(&req_data)
        .send()
        .await
        .expect("Failed to execute request.");

    delete_row(&test_app.db_pool, nip_05_id.to_string()).await;

    let response_body = response_fetch.json::<StoredKey>().await.unwrap();
    assert!(response_body.created_at.len() > 0);
    assert_eq!(private_key_hash, response_body.private_key_hash);
    assert_eq!(nip_05_id, response_body.nip_05_id);
}

#[tokio::test]
async fn fetch_key_invalid_pin() {
    let test_app = spawn_app().await;
    let client = reqwest::Client::new();
    let nip_05_id = "the_name_is_smith_bob_smith@test.com";
    let private_key_hash = "$PBKDF2$i=100000,l=256,s=0Bu5lWu4s66/iottrlUGdckjf5nwnpB05jwp4yDh8NU=$AESGM$OrScsD+hHGaRaPbc$XMXVVbjt3JV+QsNb7ZWRc8uNod2YzJL0lSvW1FOiY38ywOu7IEChKs/IqEQ7knhZAmRGYqoB4dhAbdOTwVhYIeQsuf1+f+9ARPEjtURsDg==";
    let pin = 374859;
    let form_data = json!({"nip_05_id":nip_05_id,"pin":pin, "private_key_hash":private_key_hash});
    let response_upload = client
        .post(&format!("{}/upload_key", &test_app.address))
        .json(&form_data)
        .send()
        .await
        .expect("Failed to execute request.");
    assert!(response_upload.status().is_success());

    let req_data = json!({"nip_05_id":nip_05_id, "pin":379953});
    let response_fetch = client
        .post(&format!("{}/fetch_key", &test_app.address))
        .json(&req_data)
        .send()
        .await
        .expect("Failed to execute request.");

    delete_row(&test_app.db_pool, nip_05_id.to_string()).await;

    assert_eq!(response_fetch.status(), StatusCode::FORBIDDEN);
}
