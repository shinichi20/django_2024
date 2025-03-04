import pytest
import json
from django.test import RequestFactory
from django.http import HttpResponse
from myinfo.middleware.error_handling import ErrorHandlingMiddleware

# Setup request factory
@pytest.fixture
def factory():
    return RequestFactory()

def test_middleware_handles_exception(factory):
    middleware = ErrorHandlingMiddleware(get_response=lambda req: (_ for _ in ()).throw(Exception("Test error")))

    request = factory.get("/")

    response = middleware.process_exception(request, Exception("Test error"))

    assert response.status_code == 500
    assert response["Content-Type"] == "application/json"

    # Decode JSON response
    response_data = json.loads(response.content.decode("utf-8"))

    assert "error" in response_data
    assert response_data["error"] == "Test error"

