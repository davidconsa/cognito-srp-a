# Cognito SRP helper (SRP_A + PASSWORD_CLAIM_SIGNATURE)

Herramienta en TypeScript para el login `USER_SRP_AUTH` de Cognito vía `mobile.api.dev.io.pe`:

0. **`session`** desde `POST /v1/auth/session` (va en `ClientMetadata.session`).
1. **`SRP_A`** para `InitiateAuth` (y el exponente privado `a` asociado).
2. **`PASSWORD_CLAIM_SIGNATURE`** para `RespondToAuthChallenge` (`PASSWORD_VERIFIER`).

El núcleo (`src/core/srp.ts`) usa solo `BigInt` + Web Crypto, así que el mismo código corre
en Node 18+ (CLI) y en el navegador (web).

## Web

**https://davidconsa.github.io/cognito-srp-a/**

Todo se calcula en el navegador; la web no hace llamadas HTTP.

1. Paso 0: completa `x-api-key`, `userDocument` y `recaptchaToken`, copia el `curl` y ejecútalo
   (el endpoint no permite CORS, por eso la web no lo llama). Pega la respuesta: la `session` se copia al paso 1.
2. Paso 1: completa USERNAME / ClientId y pulsa **Generar SRP_A**. Copia el body o el `curl` de `InitiateAuth`.
3. Paso 2: pega la respuesta JSON de `InitiateAuth` (con `ChallengeParameters` y `Session`), el `USER_POOL_ID`
   y el password, y pulsa **Calcular PASSWORD_CLAIM_SIGNATURE**. Copia el body o el `curl` de `RespondToAuthChallenge`.

El valor `a` queda guardado en `sessionStorage` de la pestaña para poder hacer el paso 2 después.

## CLI

```bash
npm install

# Login completo (paso 0 + 1 + 2) llamando a la API
export API_KEY='***' USER_DOCUMENT='***' RECAPTCHA_TOKEN='***'
USERNAME=<uuid> PASSWORD='***' USER_POOL_ID=us-east-1_XXXX npm run login --silent

# Solo paso 0: imprime la session y la guarda en .srp-state.json
npm run session --silent
```

| Variable | Uso |
|----------|-----|
| `API_KEY`, `USER_DOCUMENT`, `RECAPTCHA_TOKEN` | Paso 0 (`/v1/auth/session`) |
| `AUTH_FLOW` (`signup`), `APP_VERSION` (`enterprise`), `PLATFORM` (`android`) | Paso 0, opcionales |
| `SESSION` | Usa una session ya obtenida y omite el paso 0 |
| `USERNAME`, `PASSWORD`, `USER_POOL_ID` | Login |
| `CLIENT_ID`, `DEVICE`, `AUTH_ENDPOINT`, `SESSION_ENDPOINT` | Opcionales (tienen default) |

Si no se pasa `SESSION` ni `RECAPTCHA_TOKEN`, `login` usa la session guardada en `.srp-state.json` mientras no haya expirado.
Las credenciales (`API_KEY`, password, etc.) se leen solo de variables de entorno y nunca se guardan en el repo.

Pasos sueltos:

```bash
npm run generate --silent                 # imprime { a, SRP_A }
npm run generate --silent -- --raw        # solo SRP_A
npm run generate --silent -- --out        # además guarda .srp-state.json (gitignored)

# Paso 2: con la respuesta de InitiateAuth guardada en challenge.json
PASSWORD='***' USER_POOL_ID=us-east-1_XXXX npm run claim --silent -- --challenge challenge.json
```

`claim` también acepta `SRP_B`, `SALT`, `SECRET_BLOCK`, `USER_ID_FOR_SRP`, `SRP_A_PRIVATE` y `CLIENT_ID` por variables de entorno.

## Notas

- `a` es secreto y válido solo para un intento; no reutilices un `SRP_A` viejo.
- La firma incluye `TIMESTAMP`: envía `RespondToAuthChallenge` pronto después de calcularla.
- `USERNAME` en el paso 2 debe ser `USER_ID_FOR_SRP`, y `USER_POOL_ID` es el pool real (la parte tras `_` entra en la firma).
- El token `session` de `ClientMetadata` expira en minutos.

## Desarrollo

```bash
npm run typecheck   # CLI + web
npm run selftest    # simula el servidor SRP y verifica S y la firma
npm run web:dev     # servidor local de Vite
npm run web:build   # genera docs/ (publicado con GitHub Pages desde /docs)
```
