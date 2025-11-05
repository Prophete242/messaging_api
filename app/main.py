from app.messaging_kit import twilio_messaging as tm
from fastapi import FastAPI, Form, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv
from typing import Literal, Optional
import requests
import json
import uvicorn
import logging
import asyncio
import os


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")   #ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")) 

base_id = os.getenv("AIRTABLE_BASE_ID") 
table_id = os.getenv("AIRTABLE_TABLE_ID")
url = f"https://api.airtable.com/v0/{base_id}/{table_id}"
auth_token = os.getenv("AIRTABLE_API_KEY")
headers = {"Authorization": f"Bearer {auth_token}"}

def airtable_get_data():
    """
    Fetches data from Airtable using the Airtable API.

    This function sends a GET request to the specified Airtable API URL with the provided headers,
    retrieves the response data, and returns it as a JSON object.

    Returns:
        dict: A dictionary containing the response data from Airtable, parsed as JSON.
    """
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  
        data = response.json()
        return data
    except requests.exceptions.RequestException as e:
        logger.error(f"Error occurred while fetching data from Airtable: {e}")
        return []  

def json_db():
    """
    Constructs a JSON-like database from data retrieved from Airtable.

    Retrieves data from Airtable using the `airtable_get_data()` function,
    then constructs a dictionary-like database where each record's username
    serves as the key, and the record's fields, including an added 'id' field
    with the record's ID, serve as the corresponding values.

    Returns:
        dict: A dictionary representing the constructed database, with usernames
              as keys and corresponding record fields as values, including the record ID.
    """
    try:
        data = airtable_get_data()
    except Exception as e:
        logger.error(f"Error fetching data from Airtable: {e}")

    return_db = {}
    for record in data["records"]:
        record_username = record["fields"]["username"]
        record_fields = record["fields"]
        record_id = record["id"]
        record_fields["id"] = record_id
        return_db[record_username] = record_fields
    return return_db
 
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str = None

class User(BaseModel):
    username: str
    email: str = None
    full_name: str = None
    disabled: bool = None

class UserInDB(User):
    hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
#    if expires_delta:
#         expire = datetime.now() + expires_delta
#     else:
#         expire = datetime.now() + timedelta(minutes=15)
#     to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token:str = Depends(oauth2_scheme)):

    with open("app/database.json", "r") as fichier:
        db = json.load(fichier)

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# Initialize the FastAPI app
app = FastAPI(title = "NODES MESSAGING API", 
              version = "0.0.1")

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):

    db = json_db()
    with open("app/database.json", "w") as fichier:
        json.dump(db, fichier)

    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/")
async def health_check():
    """Endpoint for performing a health check."""

    return {"status": "ok"}

@app.post("/send_sms/")
async def send_sms_endpoint(
    to_phone_number: str = Form(...),
    message_body: str = Form(...),
    messaging_service_sid: str = Form(...),
    account_sid: Optional[str] = Form(None),
    auth_token: Optional[str] = Form(None),
    media_url: Optional[str] = Form(None),
    current_user: User = Depends(get_current_active_user)
):
    """
    Envoie un message SMS ou MMS via l'API Twilio.

    Args:
        to_phone_number (str): Numéro de téléphone du destinataire, au format E.164 (ex: +242XXXXXXXX).
        message_body (str): Contenu textuel du message à envoyer.
        messaging_service_sid (str): SID du service de messagerie Twilio utilisé pour l’envoi.
        account_sid (str, optional): SID du compte Twilio. Si non fourni, récupéré depuis les variables d’environnement.
        auth_token (str, optional): Token d’authentification Twilio. Si non fourni, récupéré depuis les variables d’environnement.
        media_url (str, optional): URL d’un média à inclure dans le message (pour MMS). Par défaut None.
        current_user (User): Utilisateur authentifié effectuant la requête (dépendance FastAPI).

    Returns:
        dict: 
            Un dictionnaire contenant :
                - msg_sid (str): SID unique du message envoyé.
                - msg_status (str): Statut de l’envoi du message (queued, sent, delivered, failed, etc.).

    Raises:
        HTTPException: 
            - 400 : Si les identifiants Twilio sont manquants.
            - 500 : En cas d’erreur interne ou d’échec de communication avec Twilio.
    """


    try:
        # Récupération des identifiants Twilio depuis les variables d'environnement si non fournis
        if not account_sid:
            account_sid = os.getenv("ACCOUNT_SID")
        if not auth_token:
            auth_token = os.getenv("AUTH_TOKEN")

        if not account_sid or not auth_token:
            raise HTTPException(status_code=400, detail="Identifiants Twilio manquants.")

        # Envoi du message
        call = tm.send_sms(
            to_phone_number=to_phone_number,
            message_body=message_body,
            messaging_service_sid=messaging_service_sid,
            account_sid=account_sid,
            auth_token=auth_token,
            media_url=media_url
        )

        return {"msg_sid": call[0], "msg_status": call[1]}

    except HTTPException as e:
        logger.error(f"Erreur HTTP lors de l’envoi du message : {e.detail}")
        raise e
    except Exception as e:
        logger.exception("Erreur inattendue lors de l’envoi du message.")
        raise HTTPException(status_code=500, detail=f"Erreur serveur : {str(e)}")

@app.post("/create_messaging_service/")
async def create_messaging_service_endpoint(
    service_name: str = Form(...),
    alpha_sender_id: str = Form(...),
    inbound_request_url: Optional[str] = Form(None),
    status_callback_url: Optional[str] = Form(None),
    usecase: Literal["notifications", "marketing", "verification"] = Form("marketing"),
    account_sid: Optional[str] = Form(None),
    auth_token: Optional[str] = Form(None),
    current_user: User = Depends(get_current_active_user)
):
    """
    Crée un service de messagerie Twilio avec un identifiant d’expéditeur alphanumérique.

    Args:
        service_name (str): Nom du service de messagerie à créer.
        alpha_sender_id (str): Identifiant d’expéditeur alphanumérique (par ex. “NODESAI”).
        inbound_request_url (str, optional): URL de réception des messages entrants (Webhook).
        status_callback_url (str, optional): URL de callback pour le suivi des statuts d’envoi.
        usecase (Literal): Type d’usage du service ("notifications", "marketing", "verification"). Par défaut "marketing".
        account_sid (str, optional): SID du compte Twilio. Si non fourni, récupéré depuis les variables d’environnement.
        auth_token (str, optional): Token d’authentification Twilio. Si non fourni, récupéré depuis les variables d’environnement.
        current_user (User): Utilisateur authentifié effectuant la requête (dépendance FastAPI).

    Returns:
        dict:
            Un dictionnaire contenant :
                - service_sid (str): SID unique du service de messagerie créé.
                - sender_sid (str): SID de l’expéditeur alphanumérique associé.
                - usecase (str): Type d’usage déclaré du service.
                - status (str): Résultat de l’opération ("success" ou "failed").

    Raises:
        HTTPException:
            - 400 : Si les identifiants Twilio sont manquants ou les paramètres invalides.
            - 500 : En cas d’erreur interne ou d’échec de communication avec Twilio.
    """

    try:
        # Récupération des identifiants depuis l’environnement si non fournis
        if not account_sid:
            account_sid = os.getenv("ACCOUNT_SID")
        if not auth_token:
            auth_token = os.getenv("AUTH_TOKEN")

        if not account_sid or not auth_token:
            raise HTTPException(status_code=400, detail="Identifiants Twilio manquants.")

        # Création du service via votre module Twilio Manager (tm)
        result = tm.create_messaging_service_with_alpha_sender(
            service_name=service_name,
            alpha_sender_id=alpha_sender_id,
            inbound_request_url=inbound_request_url,
            status_callback_url=status_callback_url,
            usecase=usecase,
            account_sid=account_sid,
            auth_token=auth_token
        )

        return {
            "service_sid": result.get("messaging_service_sid"),
            "sender_sid": result.get("alpha_sender_sid"),
            "usecase": usecase,
            "status": "success"
        }

    except HTTPException as e:
        logger.error(f"Erreur HTTP lors de la création du service : {e.detail}")
        raise e
    except Exception as e:
        logger.exception("Erreur inattendue lors de la création du service de messagerie.")
        raise HTTPException(status_code=500, detail=f"Erreur serveur : {str(e)}")

@app.post("/analyze_twilio_messages/")
async def analyze_twilio_messages_endpoint(
    days_back: int = Form(30),
    limit: int = Form(10000),
    account_sid: Optional[str] = Form(None),
    auth_token: Optional[str] = Form(None),
    messaging_service_sid: Optional[str] = Form(None),
    current_user: User = Depends(get_current_active_user)
):
    """
    Récupère et analyse les messages Twilio récents afin de produire des insights exploitables.

    Args:
        days_back (int, optional): Nombre de jours en arrière à considérer pour la récupération des messages. Par défaut 30.
        limit (int, optional): Nombre maximal de messages à récupérer. Par défaut 10 000.
        account_sid (str, optional): SID du compte Twilio. Si non fourni, récupéré depuis les variables d’environnement.
        auth_token (str, optional): Token d’authentification Twilio. Si non fourni, récupéré depuis les variables d’environnement.
        messaging_service_sid (str, optional): SID du service de messagerie Twilio. Si non fourni, récupéré depuis les variables d’environnement.
        current_user (User): Utilisateur authentifié effectuant la requête (dépendance FastAPI).

    Returns:
        dict:
            Un dictionnaire contenant :
                - total_messages (int): Nombre total de messages analysés.
                - period_analyzed (int): Période analysée en jours.
                - insights (dict): Données issues de l’analyse (statistiques, tendances, volumes par statut, etc.).
                - status (str): Résultat global de l’opération ("success" ou "no_data").

    Raises:
        HTTPException:
            - 400 : Si les identifiants Twilio sont manquants.
            - 500 : En cas d’erreur interne ou d’échec d’analyse.
    """

    try:
        # Récupération automatique des identifiants Twilio si non fournis
        if not account_sid:
            account_sid = os.getenv("ACCOUNT_SID")
        if not auth_token:
            auth_token = os.getenv("AUTH_TOKEN")
        if not messaging_service_sid:
            messaging_service_sid = os.getenv("MESSAGING_SERVICE_SID")

        if not account_sid or not auth_token or not messaging_service_sid:
            raise HTTPException(status_code=400, detail="Identifiants Twilio manquants.")

        # Étape 1 : Récupération des messages
        df = tm.fetch_twilio_messages(
            account_sid=account_sid,
            auth_token=auth_token,
            messaging_service_sid=messaging_service_sid,
            days_back=days_back,
            limit=limit
        )

        if df.empty:
            logger.info("Aucun message trouvé sur la période analysée.")
            return {
                "status": "no_data",
                "period_analyzed": days_back,
                "total_messages": 0,
                "insights": {}
            }

        # Étape 2 : Analyse des messages
        insights = tm.analyze_messages(df)

        return {
            "status": "success",
            "period_analyzed": days_back,
            "total_messages": len(df),
            "insights": insights
        }

    except HTTPException as e:
        logger.error(f"Erreur HTTP lors de l’analyse des messages : {e.detail}")
        raise e
    except Exception as e:
        logger.exception("Erreur inattendue lors de l’analyse des messages Twilio.")
        raise HTTPException(status_code=500, detail=f"Erreur serveur : {str(e)}")

@app.post("/send_bulk_sms/")
async def send_bulk_sms_endpoint(
    to_phone_numbers: str = Form(..., description="Liste de numéros séparés par des virgules (+242XXXXXXX,+243XXXXXXX,...)"),
    message_body: str = Form(...),
    messaging_service_sid: str = Form(...),
    account_sid: Optional[str] = Form(None),
    auth_token: Optional[str] = Form(None),
    media_url: Optional[str] = Form(None),
    current_user: User = Depends(get_current_active_user)
):
    """
    Envoie un message SMS ou MMS à plusieurs destinataires (jusqu’à 100) via l’API Twilio.

    Args:
        to_phone_numbers (str): Liste de numéros séparés par des virgules (format E.164, ex: +242XXXXXXXX,+243YYYYYYYY).
        message_body (str): Contenu textuel du message à envoyer.
        messaging_service_sid (str): SID du service de messagerie Twilio.
        account_sid (str, optional): SID du compte Twilio. Si non fourni, récupéré depuis les variables d’environnement.
        auth_token (str, optional): Token Twilio. Si non fourni, récupéré depuis les variables d’environnement.
        media_url (str, optional): URL d’un média à inclure (MMS).
        current_user (User): Utilisateur authentifié.

    Returns:
        dict:
            - total_recipients (int): Nombre de destinataires traités.
            - success_count (int): Nombre d’envois réussis.
            - failed_count (int): Nombre d’échecs.
            - results (list): Détails par numéro (statut, sid, message d’erreur éventuel).

    Raises:
        HTTPException:
            - 400 : Si les identifiants Twilio ou les numéros sont manquants.
            - 500 : En cas d’erreur interne.
    """

    try:
        # Lecture des identifiants d’environnement si non fournis
        if not account_sid:
            account_sid = os.getenv("ACCOUNT_SID")
        if not auth_token:
            auth_token = os.getenv("AUTH_TOKEN")

        if not account_sid or not auth_token:
            raise HTTPException(status_code=400, detail="Identifiants Twilio manquants.")

        # Nettoyage et parsing de la liste des numéros
        numbers = [num.strip() for num in to_phone_numbers.split(",") if num.strip()]
        if not numbers:
            raise HTTPException(status_code=400, detail="Aucun numéro valide fourni.")

        if len(numbers) > 100:
            raise HTTPException(status_code=400, detail="Le nombre maximum autorisé est 100 destinataires par requête.")

        results = []

        # Fonction interne pour envoyer un message
        async def send_one(number: str):
            try:
                call = await asyncio.to_thread(
                    tm.send_sms,
                    to_phone_number=number,
                    message_body=message_body,
                    messaging_service_sid=messaging_service_sid,
                    account_sid=account_sid,
                    auth_token=auth_token,
                    media_url=media_url
                )
                return {"to": number, "status": call[1], "msg_sid": call[0], "error": None}
            except Exception as e:
                logger.error(f"Erreur sur {number}: {e}")
                return {"to": number, "status": "failed", "msg_sid": None, "error": str(e)}

        # Envoi asynchrone simultané par lots
        tasks = [send_one(num) for num in numbers]
        results = await asyncio.gather(*tasks)

        # Statistiques globales
        success = sum(1 for r in results if r["status"] not in ("failed", "undelivered"))
        failed = len(results) - success

        return {
            "total_recipients": len(numbers),
            "success_count": success,
            "failed_count": failed,
            "results": results
        }

    except HTTPException as e:
        logger.error(f"Erreur HTTP lors de l’envoi groupé : {e.detail}")
        raise e
    except Exception as e:
        logger.exception("Erreur inattendue lors de l’envoi groupé.")
        raise HTTPException(status_code=500, detail=f"Erreur serveur : {str(e)}")
    
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload = True)