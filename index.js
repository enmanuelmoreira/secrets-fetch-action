import core from "@actions/core";
import { fetch, oidcAuth } from "./doppler.js";

// For local testing
if (process.env.NODE_ENV === "development" && process.env.DOPPLER_TOKEN) {
  process.env["INPUT_AUTH-METHOD"] = "token";
  process.env["INPUT_DOPPLER-API-DOMAIN"] = "api.doppler.com";
  process.env["INPUT_DOPPLER-TOKEN"] = process.env.DOPPLER_TOKEN;
  process.env["INPUT_DOPPLER-PROJECT"] = process.env.DOPPLER_PROJECT;
  process.env["INPUT_DOPPLER-CONFIG"] = process.env.DOPPLER_CONFIG;
}

// Función para validar si un string es JSON válido
function isValidJSON(str) {
  try {
    const parsed = JSON.parse(str);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed);
  } catch (e) {
    return false;
  }
}

// Función para validar nombres de claves
function isValidOutputKey(key) {
  return typeof key === 'string' && /^[a-zA-Z_][a-zA-Z0-9_-]*$/.test(key);
}

// Función para parsear JSON de forma segura
function safeParseJSON(jsonString, secretName) {
  try {
    const parsed = JSON.parse(jsonString);
    
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error(`Secret ${secretName} contains JSON but is not an object`);
    }
    
    // Validar que las claves sean válidas para outputs
    for (const key of Object.keys(parsed)) {
      if (!isValidOutputKey(key)) {
        core.warning(`Invalid key "${key}" in JSON secret ${secretName}, skipping this key`);
        delete parsed[key];
      }
    }
    
    return parsed;
  } catch (error) {
    throw new Error(`Failed to parse JSON secret ${secretName}: ${error.message}`);
  }
}

const AUTH_METHOD = core.getInput("auth-method");
const API_DOMAIN = core.getInput("doppler-api-domain");
let DOPPLER_TOKEN = "";

if (AUTH_METHOD === "oidc") {
  const DOPPLER_IDENTITY_ID = core.getInput("doppler-identity-id", { required: true });
  const oidcToken = await core.getIDToken();
  core.setSecret(oidcToken);
  DOPPLER_TOKEN = await oidcAuth(DOPPLER_IDENTITY_ID, oidcToken, API_DOMAIN);
} else if (AUTH_METHOD === "token") {
  DOPPLER_TOKEN = core.getInput("doppler-token", { required: true });
} else {
  core.setFailed("Unsupported auth-method");
  process.exit();
}

const DOPPLER_META = ["DOPPLER_PROJECT", "DOPPLER_CONFIG", "DOPPLER_ENVIRONMENT"];
core.setSecret(DOPPLER_TOKEN);

const IS_SA_TOKEN = DOPPLER_TOKEN.startsWith("dp.sa.") || DOPPLER_TOKEN.startsWith("dp.said.");
const IS_PERSONAL_TOKEN = DOPPLER_TOKEN.startsWith("dp.pt.");
const DOPPLER_PROJECT = (IS_SA_TOKEN || IS_PERSONAL_TOKEN) ? core.getInput("doppler-project") : null;
const DOPPLER_CONFIG = (IS_SA_TOKEN || IS_PERSONAL_TOKEN) ? core.getInput("doppler-config") : null;

if (IS_PERSONAL_TOKEN && !(DOPPLER_PROJECT && DOPPLER_CONFIG)) {
  core.setFailed("doppler-project and doppler-config inputs are required when using a Personal token. Additionally, we recommend switching to Service Accounts.");
  process.exit();
}

if (IS_SA_TOKEN && !(DOPPLER_PROJECT && DOPPLER_CONFIG)) {
  core.setFailed("doppler-project and doppler-config inputs are required when using a Service Account token");
  process.exit();
}

// NUEVOS INPUTS PARA JSON PARSING
const parseJsonSecrets = core.getInput("parse-json-secrets");
const jsonKeyPrefix = core.getInput("json-key-prefix");
const autoDetectJson = core.getInput("auto-detect-json") === "true";

// Obtener lista de secretos a parsear
const secretsToParse = parseJsonSecrets ? 
  parseJsonSecrets.split(',').map(s => s.trim()).filter(s => s.length > 0) : [];

const secrets = await fetch(DOPPLER_TOKEN, DOPPLER_PROJECT, DOPPLER_CONFIG, API_DOMAIN);

// Contadores para logging
let totalSecrets = 0;
let parsedSecrets = 0;
let parsedKeys = 0;

for (const [key, secret] of Object.entries(secrets)) {
  const value = secret.computed || "";
  totalSecrets++;
  
  // Determinar si este secreto debe ser parseado como JSON
  const shouldParseAsJson = secretsToParse.includes(key) || (autoDetectJson && isValidJSON(value));
  
  if (shouldParseAsJson && value.trim()) {
    try {
      const parsedJson = safeParseJSON(value, key);
      parsedSecrets++;
      
      // Crear outputs individuales para cada clave del JSON
      for (const [jsonKey, jsonValue] of Object.entries(parsedJson)) {
        const outputKey = jsonKeyPrefix ? `${jsonKeyPrefix}${jsonKey}` : jsonKey;
        const stringValue = typeof jsonValue === 'string' ? jsonValue : JSON.stringify(jsonValue);
        
        // Crear output
        core.setOutput(outputKey, stringValue);
        parsedKeys++;
        
        // Marcar como secreto si no es meta información
        if (!DOPPLER_META.includes(outputKey)) {
          core.setSecret(stringValue);
        }
        
        // Inyectar como variable de entorno si está habilitado
        if (core.getInput("inject-env-vars") === "true") {
          core.exportVariable(outputKey, stringValue);
        }
        
        core.info(`Parsed JSON key: ${key}.${jsonKey} -> ${outputKey}`);
      }
      
      core.info(`Successfully parsed JSON secret: ${key} (${Object.keys(parsedJson).length} keys)`);
      
    } catch (error) {
      core.warning(`Failed to parse JSON secret ${key}: ${error.message}`);
      // Continuar con el procesamiento normal si falla el parsing
    }
  }
  
  // PROCESAMIENTO NORMAL DEL SECRETO (mantener funcionalidad original)
  core.setOutput(key, value);
  
  if (!DOPPLER_META.includes(key) && secret.computedVisibility !== "unmasked") {
    core.setSecret(value);
  }
  
  if (core.getInput("inject-env-vars") === "true") {
    core.exportVariable(key, value);
  }
}

// Logging informativo
core.info(`Processed ${totalSecrets} secrets total`);
if (parsedSecrets > 0) {
  core.info(`Parsed ${parsedSecrets} JSON secrets into ${parsedKeys} individual outputs`);
}