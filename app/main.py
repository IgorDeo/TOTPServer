from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from . import models, schemas, database, totp
from .database import engine

from datetime import datetime

from dotenv import load_dotenv

load_dotenv()


models.Base.metadata.create_all(bind=engine)


app = FastAPI()
totp_generator = totp.TOTP()


@app.post("/users/", response_model=schemas.UserResponse)
def create_user(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    db_user = models.User(email=user.email, name=user.name)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.post("/users/{user_id}/generate-secret")
def generate_secret(user_id: str, db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.totp_secret:
        raise HTTPException(status_code=400, detail="Secret already generated")

    secret = totp_generator.generate_secret()
    encrypted_secret = totp.encrypt_secret(secret)

    user.totp_secret = encrypted_secret
    db.commit()

    return {"secret": secret}


@app.post("/validate-totp")
def validate_totp(
    totp_data: schemas.TOTPValidate, db: Session = Depends(database.get_db)
):
    user = db.query(models.User).filter(models.User.id == totp_data.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="TOTP not set up for this user")

    decrypted_secret = totp.decrypt_secret(user.totp_secret)
    since = user.last_totp_use.timestamp() if user.last_totp_use else None

    is_valid = totp_generator.validate_totp(
        decrypted_secret, totp_data.totp_code, since=since
    )

    if is_valid:
        user.last_totp_use = datetime.utcnow()
        db.commit()
        return {"valid": True}

    return {"valid": False}
