import azure.functions as func
import json
import logging
import os
from azure.ai.textanalytics import TextAnalyticsClient
from azure.core.credentials import AzureKeyCredential

# Create the function app instance for v2 model
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# V2 Programming Model Function
@app.route(route="redact-email", methods=["GET", "POST"])
def redact_email_v2(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function v2 para redação automática de dados sensíveis em emails.
    """
    return process_redaction_request(req)

# V1 Programming Model Function (fallback)
def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function v1 para redação automática de dados sensíveis em emails.
    """
    return process_redaction_request(req)

def process_redaction_request(req: func.HttpRequest) -> func.HttpResponse:
    """
    Processa a requisição de redação de dados sensíveis.
    
    Esta função recebe o conteúdo de um email e retorna o conteúdo com
    informações sensíveis redatadas usando Azure Cognitive Services.
    """
    logging.info('Iniciando processo de redação de dados sensíveis.')

    try:
        # Obter dados da requisição
        try:
            req_body = req.get_json()
        except ValueError:
            req_body = None
        
        if not req_body:
            # Try to get from query parameters for GET requests
            email_content = req.params.get('email_content')
            user_id = req.params.get('user_id', 'test-user')
            alert_id = req.params.get('alert_id', 'test-alert')
            
            if not email_content:
                return func.HttpResponse(
                    json.dumps({
                        "error": "Corpo da requisição não encontrado. Use POST com JSON ou GET com parâmetros.",
                        "example_post": {
                            "email_content": "Texto com dados sensíveis",
                            "user_id": "user123",
                            "alert_id": "alert456"
                        },
                        "example_get": "?email_content=texto&user_id=user123&alert_id=alert456"
                    }),
                    status_code=400,
                    mimetype="application/json"
                )
        else:
            email_content = req_body.get('email_content')
            user_id = req_body.get('user_id', 'test-user')
            alert_id = req_body.get('alert_id', 'test-alert')
        
        if not email_content:
            return func.HttpResponse(
                json.dumps({"error": "Conteúdo do email não fornecido"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Configurações do Azure Cognitive Services
        cognitive_services_endpoint = os.environ.get("COGNITIVE_SERVICES_ENDPOINT", "")
        cognitive_services_key = os.environ.get("COGNITIVE_SERVICES_KEY", "")
        
        # Se as credenciais não estiverem configuradas, simular redação para teste
        if not cognitive_services_endpoint or not cognitive_services_key:
            logging.warning("Credenciais do Azure Cognitive Services não configuradas. Usando redação simulada.")
            
            # Redação simulada para teste
            simulated_redacted = simulate_redaction(email_content)
            
            response_data = {
                "original_content": email_content,
                "redacted_content": simulated_redacted,
                "pii_entities_found": "simulated",
                "user_id": user_id,
                "alert_id": alert_id,
                "status": "success",
                "note": "Usando redação simulada - configure COGNITIVE_SERVICES_ENDPOINT e COGNITIVE_SERVICES_KEY para usar Azure Cognitive Services"
            }
            
            return func.HttpResponse(
                json.dumps(response_data),
                status_code=200,
                mimetype="application/json"
            )
        
        # Inicializar cliente do Text Analytics
        text_analytics_client = TextAnalyticsClient(
            endpoint=cognitive_services_endpoint,
            credential=AzureKeyCredential(cognitive_services_key)
        )
        
        # Detectar informações pessoais identificáveis (PII)
        pii_entities = detect_pii_entities(text_analytics_client, email_content)
        
        # Redigir o conteúdo
        redacted_content = redact_sensitive_data(email_content, pii_entities)
        
        # Preparar resposta
        response_data = {
            "original_content": email_content,
            "redacted_content": redacted_content,
            "pii_entities_found": len(pii_entities),
            "entities_details": pii_entities,
            "user_id": user_id,
            "alert_id": alert_id,
            "status": "success"
        }
        
        logging.info(f'Redação concluída. {len(pii_entities)} entidades PII encontradas.')
        
        return func.HttpResponse(
            json.dumps(response_data),
            status_code=200,
            mimetype="application/json"
        )
        
    except Exception as e:
        logging.error(f'Erro durante a redação: {str(e)}')
        return func.HttpResponse(
            json.dumps({
                "error": f"Erro interno: {str(e)}",
                "status": "error",
                "user_id": user_id if 'user_id' in locals() else "unknown",
                "alert_id": alert_id if 'alert_id' in locals() else "unknown"
            }),
            status_code=500,
            mimetype="application/json"
        )

def simulate_redaction(content):
    """
    Simula redação de dados sensíveis para teste quando Cognitive Services não está configurado.
    """
    import re
    
    # Padrões comuns de dados sensíveis
    patterns = {
        r'\b\d{3}-\d{2}-\d{4}\b': '[SSN REDATADO]',  # SSN
        r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b': '[CPF REDATADO]',  # CPF
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b': '[EMAIL REDATADO]',  # Email
        r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b': '[CARTÃO REDATADO]',  # Credit Card
        r'\b\(\d{3}\)\s?\d{3}-\d{4}\b': '[TELEFONE REDATADO]',  # Phone
        r'\b\d{3}-\d{3}-\d{4}\b': '[TELEFONE REDATADO]',  # Phone alternative
    }
    
    redacted_content = content
    for pattern, replacement in patterns.items():
        redacted_content = re.sub(pattern, replacement, redacted_content)
    
    return redacted_content

def detect_pii_entities(client, text):
    """
    Detecta entidades PII no texto usando Azure Cognitive Services.
    """
    try:
        documents = [text]
        response = client.recognize_pii_entities(documents, language="en")  # Changed to "en" for better compatibility
        
        pii_entities = []
        for doc in response:
            if not doc.is_error:
                for entity in doc.entities:
                    pii_entities.append({
                        "text": entity.text,
                        "category": entity.category,
                        "subcategory": entity.subcategory if hasattr(entity, 'subcategory') else None,
                        "confidence_score": entity.confidence_score,
                        "offset": entity.offset,
                        "length": entity.length
                    })
        
        return pii_entities
        
    except Exception as e:
        logging.error(f'Erro ao detectar entidades PII: {str(e)}')
        return []

def redact_sensitive_data(content, pii_entities):
    """
    Redige dados sensíveis no conteúdo baseado nas entidades PII detectadas.
    """
    if not pii_entities:
        return content
    
    redacted_content = content
    
    # Ordenar entidades por offset em ordem decrescente para evitar problemas de índice
    sorted_entities = sorted(pii_entities, key=lambda x: x['offset'], reverse=True)
    
    for entity in sorted_entities:
        start = entity['offset']
        end = start + entity['length']
        
        # Determinar o tipo de redação baseado na categoria
        redaction_text = get_redaction_text(entity['category'], entity.get('subcategory'))
        
        # Substituir o texto sensível
        redacted_content = (
            redacted_content[:start] + 
            redaction_text + 
            redacted_content[end:]
        )
    
    return redacted_content

def get_redaction_text(category, subcategory):
    """
    Retorna o texto de redação apropriado baseado na categoria da entidade PII.
    """
    redaction_map = {
        "Person": "[NOME REDATADO]",
        "PersonType": "[TIPO DE PESSOA REDATADO]",
        "PhoneNumber": "[TELEFONE REDATADO]",
        "Email": "[EMAIL REDATADO]",
        "Address": "[ENDEREÇO REDATADO]",
        "CreditCardNumber": "[CARTÃO DE CRÉDITO REDATADO]",
        "USSocialSecurityNumber": "[SSN REDATADO]",
        "BankAccountNumber": "[CONTA BANCÁRIA REDATADA]",
        "IPAddress": "[IP REDATADO]",
        "DateTime": "[DATA REDATADA]",
        "Quantity": "[QUANTIDADE REDATADA]",
        "Age": "[IDADE REDATADA]",
        "URL": "[URL REDATADA]"
    }
    
    return redaction_map.get(category, "[INFORMAÇÃO SENSÍVEL REDATADA]")

