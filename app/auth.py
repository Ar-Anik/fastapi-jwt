from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from app.schemas import RefreshTokenRequest, TokenResponse, UserResponse
from app.security import create_access_token, create_refresh_token, decode_token, verify_password


router = APIRouter(prefix="/auth", tags=["Authentication"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/login')

fake_users_db = {
    1: {
        "id": 1,
        "username": "anik",
        "email": "anik@example.com",
        "hashed_password": (
            "$argon2id$v=19$m=65536,t=3,p=4$"
            "wagCPXjifgvUFBzq4hqe3w$"
            "CYaIb8sB+wtD+Vu/P4uod1+Qof8h+1g7bbDlBID48Rc"
        ),
    }
}


def get_user_by_username(username: str):

    for user in fake_users_db.values():
        if user["username"] == username:
            return user

    return None


@router.post('/login', response_model=TokenResponse)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = get_user_by_username(form_data.username)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect Username or Password'
        )

    password_valid = verify_password(
        form_data.password,
        user['hashed_password']
    )

    if not password_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    access_token = create_access_token(user_id=user['id'])

    refresh_token = create_refresh_token(user_id=user['id'])

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type='bearer'
    )


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):

    try:
        payload = decode_token(token)

    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token required",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

    user_id = payload.get("sub")

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    user = fake_users_db.get(int(user_id))

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return user


@router.get('/me', response_model=UserResponse)
async def get_me(current_user: Annotated[dict, Depends(get_current_user)]):
    return UserResponse(
        username=current_user["username"],
        email=current_user["email"],
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshTokenRequest):

    try:
        payload = decode_token(request.refresh_token)

    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )


    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token required",
        )

    user_id = payload.get("sub")

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    user = fake_users_db.get(int(user_id))

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    new_access_token = create_access_token(user_id=user["id"])

    new_refresh_token = create_refresh_token(user_id=user["id"])

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
    )
