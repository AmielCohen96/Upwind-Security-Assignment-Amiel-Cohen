import { Router, Request, Response } from 'express';
import { Prisma } from '@prisma/client';
import { z } from 'zod';
import bcrypt from 'bcrypt';
import { requireAuth, requireRole } from '../middleware/auth.js';
import prisma from '../lib/prisma.js';

const router = Router();

// .strict() rejects extra/unknown fields to prevent parameter pollution attacks.
// .min(8) aligns with the login schema and enforces a minimum complexity baseline.
const createUserSchema = z.object({
  email: z.string().email('Valid email required'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  role: z.string().min(1, 'Role is required'),
}).strict();

// GET /api/users: Fetch all users with admin-only access.
// This endpoint is protected with both requireAuth (user must be logged in)
// and requireRole(['admin']) (user must have admin role).
// The passwordHash field is explicitly excluded from the response to prevent
// exposing sensitive credential data.
router.get('/', requireAuth, requireRole(['admin']), async (req: Request, res: Response) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        email: true,
        role: true,
        status: true,
      },
    });
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to load users' });
  }
});

// POST /api/users: Create a new user (admin-only).
router.post('/', requireAuth, requireRole(['admin']), async (req: Request, res: Response) => {
  try {
    const { email, password, role } = createUserSchema.parse(req.body);
    const passwordHash = await bcrypt.hash(password, 10);

    const createdUser = await prisma.user.create({
      data: {
        email,
        passwordHash,
        role,
      },
      select: {
        id: true,
        email: true,
        role: true,
        status: true,
      },
    });

    res.status(201).json(createdUser);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Invalid input', details: error.errors });
    }

    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
      return res.status(400).json({ error: 'A user with that email already exists' });
    }

    console.error('Error creating user:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// DELETE /api/users/:id: Delete a user by id (admin-only).
router.delete('/:id', requireAuth, requireRole(['admin']), async (req: Request, res: Response) => {
  const { id } = req.params;

  // Prevent an admin from deleting their own account and locking themselves out.
  if (id === req.user?.id) {
    return res.status(400).json({ error: 'You cannot delete or disable your own account.' });
  }

  try {
    await prisma.user.delete({
      where: { id },
    });
    res.status(204).send();
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2025') {
      return res.status(404).json({ error: 'User not found' });
    }

    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// PATCH /api/users/:id/status: Toggle a user's active/inactive status (admin-only).
router.patch('/:id/status', requireAuth, requireRole(['admin']), async (req: Request, res: Response) => {
  const { id } = req.params;

  // Prevent an admin from disabling their own account and locking themselves out.
  if (id === req.user?.id) {
    return res.status(400).json({ error: 'You cannot delete or disable your own account.' });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id },
      select: { status: true },
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const nextStatus = user.status === 'active' ? 'inactive' : 'active';

    const updatedUser = await prisma.user.update({
      where: { id },
      data: { status: nextStatus },
      select: { id: true, status: true },
    });

    res.json(updatedUser);
  } catch (error) {
    console.error('Error toggling user status:', error);
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

export default router;
