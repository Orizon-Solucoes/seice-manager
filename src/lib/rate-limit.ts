import { createHash } from "node:crypto";
import type { RowDataPacket } from "mysql2/promise";
import { pool } from "@/lib/db";

const LIMITE_TENTATIVAS = 5;
const JANELA_MINUTOS = 15;
let inicializacao: Promise<void> | null = null;

interface LimiteRow extends RowDataPacket {
  tentativas: number;
  bloqueado_ate: Date | string | null;
}

async function garantirTabela() {
  if (!inicializacao) {
    inicializacao = pool.query(
      `CREATE TABLE IF NOT EXISTS auth_rate_limits (
        chave CHAR(64) NOT NULL PRIMARY KEY,
        tentativas INT UNSIGNED NOT NULL DEFAULT 0,
        janela_inicio DATETIME NOT NULL,
        bloqueado_ate DATETIME NULL,
        atualizado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
          ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_auth_rate_limits_bloqueio (bloqueado_ate)
      )`,
    ).then(() => undefined).catch((error) => {
      inicializacao = null;
      throw error;
    });
  }
  await inicializacao;
}

export function criarChaveLimite(request: Request, identificador: string) {
  const cabecalhoIp = request.headers.get("x-real-ip")
    ?? request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    ?? "ip-indisponivel";
  return createHash("sha256")
    .update(`${cabecalhoIp}:${identificador.trim().toLowerCase()}`)
    .digest("hex");
}

export async function verificarLimite(chave: string) {
  await garantirTabela();
  const [rows] = await pool.execute<LimiteRow[]>(
    `SELECT tentativas, bloqueado_ate
     FROM auth_rate_limits
     WHERE chave = ? AND bloqueado_ate > NOW()
     LIMIT 1`,
    [chave],
  );
  const row = rows[0];
  if (!row?.bloqueado_ate) return { permitido: true, aguardarSegundos: 0 };
  const restante = Math.max(
    1,
    Math.ceil((new Date(row.bloqueado_ate).getTime() - Date.now()) / 1000),
  );
  return { permitido: false, aguardarSegundos: restante };
}

export async function registrarFalha(chave: string) {
  await garantirTabela();
  await pool.execute(
    `INSERT INTO auth_rate_limits
       (chave, tentativas, janela_inicio, bloqueado_ate)
     VALUES (?, 1, NOW(), NULL)
     ON DUPLICATE KEY UPDATE
       bloqueado_ate = IF(
         janela_inicio < DATE_SUB(NOW(), INTERVAL ${JANELA_MINUTOS} MINUTE),
         NULL,
         IF(tentativas + 1 >= ${LIMITE_TENTATIVAS},
           DATE_ADD(NOW(), INTERVAL ${JANELA_MINUTOS} MINUTE),
           bloqueado_ate)
       ),
       tentativas = IF(
         janela_inicio < DATE_SUB(NOW(), INTERVAL ${JANELA_MINUTOS} MINUTE),
         1,
         tentativas + 1
       ),
       janela_inicio = IF(
         janela_inicio < DATE_SUB(NOW(), INTERVAL ${JANELA_MINUTOS} MINUTE),
         NOW(),
         janela_inicio
       )`,
    [chave],
  );
}

export async function limparLimite(chave: string) {
  await garantirTabela();
  await pool.execute("DELETE FROM auth_rate_limits WHERE chave = ?", [chave]);
}

export function respostaRateLimit(aguardarSegundos: number) {
  return {
    status: 429,
    headers: {
      "Cache-Control": "no-store",
      "Retry-After": String(aguardarSegundos),
    },
  };
}
