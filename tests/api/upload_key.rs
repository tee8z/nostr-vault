use crate::helpers::spawn_app;
use nostr_vault::authentication::StoredKey;
use serde_json::json;

#[tokio::test]
async fn upload_key_works() {
    let test_app = spawn_app().await;
    let client = reqwest::Client::new();
    let nip_05_id = "the_name_is_smith_bob_smith@test.com";
    let private_key_hash = "5ed7b5ea7564ae34a282bb94a7977b3ca0814d241d0b5794c4cf5f0b80280b3a";
    let form_data = json!({"nip_05_id":nip_05_id,"pin":374859, "pk":private_key_hash});
    let response = client
        .post(&format!("{}/upload_key", &test_app.address))
        .json(&form_data)
        .send()
        .await
        .expect("Failed to execute request.");
    assert!(response.status().is_success());

    let response_body = response.json::<StoredKey>().await.unwrap();

    let saved = sqlx::query!(
        r#"SELECT id, pin_hash, private_key_hash, created_at 
        FROM keys 
        WHERE nip_05_id = $1"#,
        nip_05_id
    )
    .fetch_one(&test_app.db_pool)
    .await
    .expect("Failed to fetch saved key");

    sqlx::query!(
        r#"DELETE 
        FROM keys
        WHERE nip_05_id = $1"#,
        nip_05_id
    )
    .execute(&test_app.db_pool)
    .await
    .expect("Failed to clean up inserted value");

    assert_eq!(saved.private_key_hash, private_key_hash);
    assert!(saved.pin_hash.len() > 0);
    assert_eq!(saved.created_at.to_rfc3339(), response_body.created_at);
    assert_eq!(saved.id, response_body.id);
    assert_eq!(nip_05_id, response_body.nip_05_id);
}
