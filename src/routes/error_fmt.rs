use utoipa::ToSchema;

pub fn error_chain_fmt(
    e: &impl std::error::Error,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    writeln!(f, "{}\n", e)?;
    let mut current = e.source();
    while let Some(cause) = current {
        writeln!(f, "Caused by:\n\t{}", cause)?;
        current = cause.source();
    }
    Ok(())
}

#[derive(ToSchema, serde::Serialize, serde::Deserialize)]
pub struct ErrorResponse {
    #[schema(example = "8ehd99 is not a valid pin.")]
    pub value: String,
}
