from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
import logging

logger = logging.getLogger(__name__)

class ErrorHandlingMiddleware(MiddlewareMixin):
    def process_exception(self, request, exception):
        logger.error(f"Exception caught: {exception}")
        response_data = {
            "error": "Internal Server Error",
            "message": str(exception)
        }
        return JsonResponse(response_data, status=500)
