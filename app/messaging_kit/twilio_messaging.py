from twilio.rest import Client
from datetime import datetime, timedelta
from typing import Literal, Optional
import pandas as pd

def send_sms(to_phone_number: str,
             message_body: str, 
             media_url: Optional[list] = None,
             messaging_service_sid: Optional[str] = None,
             account_sid: Optional[str] = None,
             auth_token: Optional[str] = None) -> tuple:
    """
    Envoie un message SMS ou MMS via Twilio.
    
    Args:
        to_phone_number (str): Numéro de téléphone du destinataire avec indicatif pays
        message_body (str): Contenu du message texte à envoyer
        media_url (list, optional): Liste d'URLs vers des fichiers média pour MMS
        messaging_service_sid (str, optional): SID du service de messagerie Twilio à utiliser
        account_sid (str, optional): SID du compte Twilio
        auth_token (str, optional): Token d'authentification Twilio
    
    Returns:
        tuple: (message_sid, status) - SID du message et son statut d'envoi
        
    Raises:
        Exception: En cas d'erreur lors de l'envoi du message
        
    """
    try:
        # Initialisation du client Twilio
        client = Client(account_sid, auth_token)

        args = {
            "body": message_body,
            "messaging_service_sid": messaging_service_sid,
            "to": to_phone_number
        }
        
        if media_url:
            args["media_url"] = media_url
            args["send_as_mms"] = True
        
        # Envoi du message
        message = client.messages.create(**args)
                
        return message.sid, message.status
        
    except Exception as e:
        raise e

def create_messaging_service_with_alpha_sender(
    service_name: str,
    alpha_sender_id: str,
    inbound_request_url: Optional[str] = None,
    status_callback_url: Optional[str] = None,
    usecase: Literal["notifications", "marketing", "verification"] = "marketing",
    account_sid: Optional[str] = None,
    auth_token: Optional[str] = None
) -> dict:
    """
    Crée un service de messagerie Twilio et y ajoute un identifiant d'expéditeur alphanumérique.
    
    Args:
        service_name (str): Nom convivial pour le service de messagerie
        alpha_sender_id (str): Identifiant alphanumérique de l'expéditeur (ex: 'VotreMarque')
                               Doit contenir entre 3 et 11 caractères alphanumériques
        account_sid (str, optional): SID du compte Twilio
        auth_token (str, optional): Token d'authentification Twilio
        inbound_request_url (str, optional): URL webhook pour les messages entrants
        status_callback_url (str, optional): URL webhook pour les callbacks de statut
        usecase (str, optional): Type d'utilisation du service. Options: 
                                 'notifications', 'marketing', 'verification'
                                 Par défaut: 'marketing'
    
    Returns:
        dict: Dictionnaire contenant:
            - success (bool): Indicateur de succès
            - messaging_service_sid (str): SID du service de messagerie créé
            - messaging_service_name (str): Nom du service de messagerie
            - alpha_sender_sid (str): SID de l'alpha sender créé
            - alpha_sender_id (str): Identifiant de l'alpha sender
            
    Raises:
        Exception: En cas d'erreur lors de la création du service ou de l'alpha sender
        
    """
    try:
        # Étape 1: Création du service de messagerie
        client = Client(account_sid, auth_token)

        service_params = {
            "friendly_name": service_name,
            "use_inbound_webhook_on_number": False,
            "usecase": usecase
        }
        
        if inbound_request_url:
            service_params["inbound_request_url"] = inbound_request_url
            
        if status_callback_url:
            service_params["status_callback"] = status_callback_url
        
        messaging_service = client.messaging.v1.services.create(**service_params)
        
        messaging_service_sid = messaging_service.sid        

        # Étape 2: Ajout de l'alpha sender au service
        alpha_sender = client.messaging.v1.services(messaging_service_sid) \
            .alpha_senders \
            .create(alpha_sender=alpha_sender_id)
        
        alpha_sender_sid = alpha_sender.sid
        
        return {
            "success": True,
            "messaging_service_sid": messaging_service_sid,
            "messaging_service_name": service_name,
            "alpha_sender_sid": alpha_sender_sid,
            "alpha_sender_id": alpha_sender_id
        }
        
    except Exception as e:
        raise e

def fetch_twilio_messages(
    account_sid: str,
    auth_token: str,
    messaging_service_sid: Optional[str] = None,
    days_back: int = 7,
    limit: int = 10000
) -> pd.DataFrame:
    """
    Fetch messages from Twilio and return as a pandas DataFrame.
    
    Args:
        account_sid: Your Twilio Account SID
        auth_token: Your Twilio Auth Token
        messaging_service_sid: Optional Messaging Service SID to filter by
        days_back: Number of days to look back (default: 7)
        limit: Maximum number of messages to fetch (default: 10000)
    
    Returns:
        DataFrame with message data
    """
    
    # Initialize Twilio client
    client = Client(account_sid, auth_token)
    
    # Calculate date range
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days_back)
        
    # Fetch messages
    messages = client.messages.list(
        date_sent_after=start_date,
        limit=limit
    )
    
    # Convert to list of dictionaries
    message_data = []
    for msg in messages:
        # Skip if filtering by messaging service
        if messaging_service_sid and msg.messaging_service_sid != messaging_service_sid:
            continue
            
        message_data.append({
            'sid': msg.sid,
            'date_sent': msg.date_sent,
            'date_created': msg.date_created,
            'date_updated': msg.date_updated,
            'from': msg.from_,
            'to': msg.to,
            'body': msg.body,
            'status': msg.status,
            'direction': msg.direction,
            'price': float(msg.price) if msg.price else 0.0,
            'price_unit': msg.price_unit,
            'error_code': msg.error_code,
            'error_message': msg.error_message,
            'num_segments': msg.num_segments,
            'num_media': msg.num_media,
            'messaging_service_sid': msg.messaging_service_sid,
        })
    
    # Create DataFrame
    df = pd.DataFrame(message_data)
    
    if df.empty:
        return df
    
    # Data processing
    df['date_sent'] = pd.to_datetime(df['date_sent'])
    df['date'] = df['date_sent'].dt.date
    df['hour'] = df['date_sent'].dt.hour
    df['day_of_week'] = df['date_sent'].dt.day_name()
    df['price_abs'] = df['price'].abs()
    # Convert numeric columns to proper types
    df['num_segments'] = pd.to_numeric(df['num_segments'], errors='coerce').fillna(0).astype(int)
    df['num_media'] = pd.to_numeric(df['num_media'], errors='coerce').fillna(0).astype(int)

    return df

def analyze_messages(df: pd.DataFrame) -> dict:
    """
    Analyze message DataFrame and return insights.
    
    Args:
        df: DataFrame with message data from fetch_twilio_messages()
    
    Returns:
        Dictionary with summary insights and analytics
    """
    
    if df.empty:
        return {}
    
    # Calculate insights
    insights = {
        'total_messages': len(df),
        'total_cost': df['price_abs'].sum(),
        'average_price': df['price_abs'].mean(),
        'median_price': df['price_abs'].median(),
        'status_breakdown': df['status'].value_counts().to_dict(),
        'direction_breakdown': df['direction'].value_counts().to_dict(),
        'successful_deliveries': int(df['status'].isin(['delivered', 'sent', 'received']).sum()),
        'failed_deliveries': int(df['status'].isin(['failed', 'undelivered']).sum()),
        'pending_messages': int(df['status'].isin(['queued', 'sending', 'accepted']).sum()),
        'delivery_rate': (df['status'].isin(['delivered', 'sent', 'received']).sum() / len(df) * 100) if len(df) > 0 else 0,
        'failure_rate': (df['status'].isin(['failed', 'undelivered']).sum() / len(df) * 100) if len(df) > 0 else 0,
        'daily_volume': df.groupby('date').size().to_dict(),
        'hourly_distribution': df.groupby('hour').size().to_dict(),
        'day_of_week_distribution': df['day_of_week'].value_counts().to_dict(),
        'avg_segments_per_message': df['num_segments'].mean(),
        'total_segments': int(df['num_segments'].sum()),
        'messages_with_media': int((df['num_media'] > 0).sum()),
        'total_media_items': int(df['num_media'].sum()),
    }
    
    # Date range from data
    if 'date_sent' in df.columns:
        insights['date_range'] = {
            'start': df['date_sent'].min().isoformat(),
            'end': df['date_sent'].max().isoformat()
        }
    
    # Error analysis
    error_df = df[df['error_code'].notna()]
    if not error_df.empty:
        insights['error_code_breakdown'] = error_df['error_code'].value_counts().to_dict()
        insights['total_errors'] = len(error_df)
    
    return insights


