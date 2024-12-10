import os
import re
import httpx
import html
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, HTTPException, status, Request, Response, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from mongoengine import *

# local script
from schema.user import User

#import requests
import time

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    connect(host="mongodb+srv://iniUser:WjYh5RtjZbscH9wK@cluster0.0rsk1.mongodb.net/db_ventix?retryWrites=true&w=majority&appName=Cluster0")
    yield

app = FastAPI(lifespan=lifespan)

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def catch_all(path: str, request: Request):
    registered_paths = [
        {
            "format":r"^token",
            "target":"",
            "process_inside": True,
            "function_executor": login_for_access_token,
            "specific_method_used": "POST",
            "need_form_data": True,
            "auth": False,
            "allowed_role": []
        },
        {
            "format":r"^register",
            "target":"",
            "process_inside": True,
            "function_executor": register,
            "specific_method_used": "POST",
            "need_form_data": True,
            "auth": False,
            "allowed_role": []
        },
        {
            "format":r"^participant",
            "target":"https://intero-partisipan-production.up.railway.app",
            "process_inside": False,
            "function_executor": None,
            "specific_method_used": "",
            "need_form_data": False,
            "auth": True,
            "allowed_role": ["participant"]
        },
        {
            "format":r"^api/v1/events",
            "target":"https://ventix-event-production.up.railway.app",
            "process_inside": False,
            "function_executor": None,
            "specific_method_used": "",
            "need_form_data": False,
            "auth": True,
            "allowed_role": ["organizer", "owner"]
        },
        {
            "format":r"^api/v1/cms/categories",
            "target":"https://interoperabilitas-production.up.railway.app",
            "process_inside": False,
            "function_executor": None,
            "specific_method_used": "",
            "need_form_data": False,
            "auth": True,
            "allowed_role": ["organizer"]
        },
        # {
        #     "format":r"^api/v1/cms/orders",
        #     "target":"https://interoperabilitas-production.up.railway.app",
        #     "process_inside": False,
        #     "function_executor": None,
        #     "specific_method_used": "",
        #     "need_form_data": False,
        #     "auth": True,
        #     "allowed_role": ["organizer", "owner"]
        # },
        {
            "format":r"^api/v1/cms/talents",
            "target":"https://intero.nibdo.dev",
            "process_inside": False,
            "function_executor": None,
            "specific_method_used": "",
            "need_form_data": False,
            "auth": False,
            "allowed_role": []
        },
        {
            "format":r"^api/v1/cms/payment",
            "target":"https://api-payments-485701353107.us-central1.run.app",
            "process_inside": False,
            "function_executor": None,
            "specific_method_used": "",
            "need_form_data": False,
            "auth": False,
            "allowed_role": ["participant"]
        },
    ]

    for registered_path in registered_paths:
        if re.match(registered_path["format"], path):
            if registered_path["auth"]:
                try:
                    token = await oauth2_scheme(request)
                    current_user = await get_current_user(token)
                    
                    if registered_path["allowed_role"] and not current_user.role in registered_path["allowed_role"]:
                        return Response(
                            content="unauthorized request",
                            status_code=401
                        )

                    user = await get_current_active_user(current_user)
                except HTTPException as exc:
                    return Response(
                        content=exc.detail,
                        status_code=exc.status_code,
                        headers=exc.headers
                    )
            
            if registered_path["process_inside"]:
                if registered_path["specific_method_used"] and registered_path["specific_method_used"] == request.method:
                    if callable(registered_path["function_executor"]):
                        if registered_path["need_form_data"]:
                            form_data = await request.form()
                            return await registered_path["function_executor"](form_data)
                        return await registered_path["function_executor"]()
                    else:
                        return Response(
                            content="Function executor is not callable",
                            status_code=500
                        )
            else:
                # Proxy logic
                target_url = f"{registered_path['target']}/{path}".rstrip("/")
                headers = {key: value for key, value in request.headers.items() if key.lower() != 'host'}

                if registered_path["auth"]:
                    headers['user'] = str(current_user.id)

                if 'authorization' in request.headers:
                    headers['Authorization'] = request.headers['authorization']

                async with httpx.AsyncClient() as client:
                    try:
                        body = await request.body()
                        response = await client.request(
                            method=request.method,
                            url=target_url,
                            headers=headers,
                            params=request.query_params,
                            content=body,
                        )
                        excluded_headers = ['content-encoding', 'transfer-encoding', 'content-length']
                        response_headers = {
                            key: value for key, value in response.headers.items()
                            if key.lower() not in excluded_headers
                        }
                        return Response(
                            content=response.content,
                            status_code=response.status_code,
                            headers=response_headers,
                            media_type=response.headers.get('content-type')
                        )
                    except httpx.RequestError as exc:
                        print(f"Request error: {exc}")
                        return Response(
                            content=f"An error occurred while requesting {exc.request.url!r}.",
                            status_code=502
                        )

    # If no match is found
    return Response(content="Path not found", status_code=404)



@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.perf_counter()
    response = await call_next(request)
    process_time = time.perf_counter() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


def get_user(username: str):
    return User.objects(username=username).first()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, os.getenv("SECRET_KEY"), algorithm=os.getenv("ALGORITHM"))
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=[os.getenv("ALGORITHM")])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def login_for_access_token(form_data) -> Token:
    user = authenticate_user(form_data.get("username"), form_data.get("password"))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=float(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")))
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


async def register(form_data) -> Token:
    User(
        username=html.escape(form_data.get("username")),
        email=html.escape(form_data.get("email")),
        hashed_password=get_password_hash(html.escape(form_data.get("password"))),
        disabled=False, role="participant").save()
    user = authenticate_user(form_data.get("username"), form_data.get("password"))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=float(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")))
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")    


async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return [{"item_id": "Foo", "owner": current_user.username}]