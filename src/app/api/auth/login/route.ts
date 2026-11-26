import { NextResponse } from "next/server";
import type { RowDataPacket } from "mysql2/promise";
import { pool } from "@/lib/db";
import { criarSessao, normalizarPerfil, verificarSenha } from "@/lib/auth";
import {
  criarChaveLimite,
  limparLimite,
  registrarFalha,
  respostaRateLimit,
  verificarLimite,
} from "@/lib/rate-limit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

interface UsuarioRow extends RowDataPacket {
  id: string;
  nome: string;
  usuario: string;
  senha_hash: string | null;
  ativo: number;
  perfil: string;
  unidade_id: string | null;
}

export async function POST(request: Request) {
  try {
    const entrada: unknown = await request.json();
    if (!entrada || typeof entrada !== "object" || Array.isArray(entrada)) {
      return NextResponse.json({ erro: "Dados inválidos." }, { status: 400 });
    }

    const body = entrada as Record<string, unknown>;
    const usuario = typeof body.usuario === "string" ? body.usuario.trim().toLowerCase() : "";
    const senha = typeof body.senha === "string" ? body.senha : "";

    if (!usuario || !senha || usuario.length > 100 || senha.length > 128) {
      return NextResponse.json({ erro: "Usuário ou senha inválidos." }, { status: 401, headers: { "Cache-Control": "no-store" } });
    }

    const chaveLimite = criarChaveLimite(request, usuario);
    const limite = await verificarLimite(chaveLimite);
    if (!limite.permitido) {
      return NextResponse.json(
        { erro: "Muitas tentativas. Aguarde antes de tentar novamente." },
        respostaRateLimit(limite.aguardarSegundos),
      );
    }

    const [rows] = await pool.execute<UsuarioRow[]>(
      `SELECT id, nome, usuario, senha_hash, ativo, perfil, unidade_id
       FROM usuarios
       WHERE usuario = ?
       LIMIT 1`,
      [usuario],
    );

    const conta = rows[0];
    const senhaValida = Boolean(
      conta &&
      Number(conta.ativo) === 1 &&
      conta.senha_hash &&
      verificarSenha(senha, conta.senha_hash),
    );

    if (!senhaValida || !conta) {
      await registrarFalha(chaveLimite);
      return NextResponse.json(
        { erro: "Usuário ou senha inválidos." },
        { status: 401, headers: { "Cache-Control": "no-store" } },
      );
    }

    await limparLimite(chaveLimite);
    const token = await criarSessao(conta.id);
    const perfil = normalizarPerfil(conta.perfil);

    const resposta = NextResponse.json(
      {
        sucesso: true,
        usuario: {
          id: conta.id,
          nome: conta.nome,
          usuario: conta.usuario,
          perfil,
          unidade_id: perfil === "admin" ? "AMBOS" : conta.unidade_id ?? "AMBOS",
          administradorGeral: perfil === "admin",
        },
      },
      { headers: { "Cache-Control": "no-store" } },
    );

    resposta.cookies.set("cm_session", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 7 * 24 * 60 * 60,
    });
    return resposta;
  } catch (error) {
    console.error("Erro no login:", error);
    return NextResponse.json(
      { erro: "Não foi possível realizar o login." },
      { status: 500, headers: { "Cache-Control": "no-store" } },
    );
  }
}
