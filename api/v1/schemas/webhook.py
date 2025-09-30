from pydantic import Field, BaseModel, HttpUrl, model_validator


class WebhookUrlCreate(BaseModel):
    url: HttpUrl = Field(
        ...,
        description="Webhook URL where the event data will be sent",
        min_length=12,
        max_length=200,
    )
