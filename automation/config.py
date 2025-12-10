# config.py

import os

# Base URL for the API service
BASE_URL = os.getenv("BASE_API_URL", "http://localhost:5000")

# HTTP Status Codes (as per requirement)
HTTP_200_OK = 200
HTTP_201_CREATED = 201
HTTP_202_ACCEPTED = 202
HTTP_400_BAD_REQUEST = 400
HTTP_401_UNAUTHORIZED = 401
HTTP_403_FORBIDDEN = 403
HTTP_500_SERVER_ERROR = 500