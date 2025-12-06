import { Router, Request, Response } from 'express';
import prisma from '../prisma'; 
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const router = Router();
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret'; 
router.post('/login', async (req: Request, res: Response) => {
  const { email, senha } = req.body; 
 
  const usuario = await prisma.usuario.findUnique({
    where: { email },
  });

  if (!usuario) {

    return res.status(401).json({ message: 'Credenciais inválidas.' });
  }

  const senhaValida = await bcrypt.compare(senha, usuario.senha);

  if (!senhaValida) {
    return res.status(401).json({ message: 'Credenciais inválidas.' });
  }

  const token = jwt.sign(
    { userId: usuario.id, email: usuario.email },
    JWT_SECRET,
    { expiresIn: '1d' } 
  );

  return res.json({ token, nome: usuario.nome });
});

export default router;
