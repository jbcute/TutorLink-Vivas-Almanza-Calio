// @ts-ignore: using 'jose' library without full type deps in this environment
import { SignJWT, jwtVerify } from 'jose';

interface Env {
  // D1Database types aren't available in this environment checker — use any for now
  DB: any;
}

// Simple SHA-256 hash
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Generate JWT token
async function generateToken(user: any): Promise<string> {
  const secret = new TextEncoder().encode('codedemia-secret-key-2024');
  return await new SignJWT({ id: user.id, email: user.email, role: user.role, name: user.name })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime('24h')
    .sign(secret);
}

// Verify JWT token
async function verifyToken(token: string): Promise<any> {
  try {
    const secret = new TextEncoder().encode('codedemia-secret-key-2024');
    const { payload } = await jwtVerify(token, secret);
    return payload;
  } catch {
    return null;
  }
}

// Get user from token
async function getCurrentUser(request: Request, env: Env): Promise<any> {
  const authHeader = request.headers.get('Authorization');
  const cookieHeader = request.headers.get('Cookie');
  
  let token = null;
  if (authHeader?.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  } else if (cookieHeader) {
    const match = cookieHeader.match(/token=([^;]+)/);
    if (match) token = match[1];
  }
  
  if (!token) return null;
  
  const payload = await verifyToken(token);
  if (!payload) return null;
  
  const user = await env.DB.prepare(
    'SELECT id, name, email, role, profile_picture, age, gender, experience FROM users WHERE id = ?'
  ).bind(payload.id).first();
  
  return user;
}

// Main handler
export async function onRequest(context: any): Promise<Response> {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // CORS headers
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Content-Type': 'application/json',
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // ========== REGISTER ==========
    if (path === '/api/register' && request.method === 'POST') {
      const body = await request.json();
      
      const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?')
        .bind(body.email).first();
      
      if (existing) {
        return new Response(JSON.stringify({ success: false, message: 'Email already registered' }), 
          { status: 409, headers: corsHeaders });
      }
      
      const hashedPassword = await hashPassword(body.password);
      
      await env.DB.prepare(
        'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)'
      ).bind(body.name, body.email, hashedPassword, body.role).run();
      
      const user = await env.DB.prepare(
        'SELECT id, name, email, role FROM users WHERE email = ?'
      ).bind(body.email).first();
      
      const token = await generateToken(user);
      
      return new Response(JSON.stringify({ success: true, user, token }), {
        status: 201,
        headers: { ...corsHeaders, 'Set-Cookie': `token=${token}; HttpOnly; Secure; SameSite=Lax; Max-Age=86400; Path=/` }
      });
    }

    // ========== LOGIN ==========
    if (path === '/api/login' && request.method === 'POST') {
      const body = await request.json();
      
      const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?')
        .bind(body.email).first();
      
      if (!user) {
        return new Response(JSON.stringify({ success: false, message: 'Invalid credentials' }), 
          { status: 401, headers: corsHeaders });
      }
      
      const hashedPassword = await hashPassword(body.password);
      if (hashedPassword !== user.password) {
        return new Response(JSON.stringify({ success: false, message: 'Invalid credentials' }), 
          { status: 401, headers: corsHeaders });
      }
      
      const { password, ...userWithoutPassword } = user;
      const token = await generateToken(userWithoutPassword);
      
      return new Response(JSON.stringify({ success: true, user: userWithoutPassword, token }), {
        status: 200,
        headers: { ...corsHeaders, 'Set-Cookie': `token=${token}; HttpOnly; Secure; SameSite=Lax; Max-Age=86400; Path=/` }
      });
    }

    // ========== LOGOUT ==========
    if (path === '/api/logout' && request.method === 'POST') {
      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { ...corsHeaders, 'Set-Cookie': 'token=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/' }
      });
    }

    // ========== GET PROFILE ==========
    if (path === '/api/profile' && request.method === 'GET') {
      const user = await getCurrentUser(request, env);
      if (!user) {
        return new Response(JSON.stringify({ success: false, message: 'Unauthorized' }), 
          { status: 401, headers: corsHeaders });
      }
      return new Response(JSON.stringify({ success: true, user }), { headers: corsHeaders });
    }

    // ========== UPDATE PROFILE ==========
    if (path === '/api/profile' && request.method === 'PUT') {
      const user = await getCurrentUser(request, env);
      if (!user) {
        return new Response(JSON.stringify({ success: false, message: 'Unauthorized' }), 
          { status: 401, headers: corsHeaders });
      }
      
      const body = await request.json();
      
      await env.DB.prepare(`
        UPDATE users SET 
          name = COALESCE(?, name),
          age = COALESCE(?, age),
          gender = COALESCE(?, gender),
          experience = COALESCE(?, experience),
          goal = COALESCE(?, goal),
          bio = COALESCE(?, bio),
          profile_picture = COALESCE(?, profile_picture),
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(
        body.name, body.age, body.gender, body.experience, 
        body.goal, body.bio, body.profile_picture, user.id
      ).run();
      
      const updated = await env.DB.prepare(
        'SELECT id, name, email, role, profile_picture, age, gender, experience, goal, bio FROM users WHERE id = ?'
      ).bind(user.id).first();
      
      return new Response(JSON.stringify({ success: true, user: updated }), { headers: corsHeaders });
    }

    // ========== GET TUTORS ==========
    if (path === '/api/tutors' && request.method === 'GET') {
      const tutors = await env.DB.prepare(
        'SELECT id, name, email, experience, bio, profile_picture FROM users WHERE role = ?'
      ).bind('professor').all();
      
      return new Response(JSON.stringify({ success: true, tutors: tutors.results }), { headers: corsHeaders });
    }

    // ========== CREATE BOOKING ==========
    if (path === '/api/bookings/create' && request.method === 'POST') {
      const user = await getCurrentUser(request, env);
      if (!user) {
        return new Response(JSON.stringify({ success: false, message: 'Unauthorized' }), 
          { status: 401, headers: corsHeaders });
      }
      
      const body = await request.json();
      
      const result = await env.DB.prepare(`
        INSERT INTO bookings (student_id, tutor_id, language, date, time, duration, meeting_type, location, platform, notes, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
      `).bind(
        user.id, body.tutor_id, body.language, body.date, body.time, 
        body.duration, body.meeting_type, body.location || '', body.platform || '', body.notes || ''
      ).run();
      
      return new Response(JSON.stringify({ success: true, booking_id: result.meta.last_row_id }), 
        { status: 201, headers: corsHeaders });
    }

    // ========== GET BOOKINGS (STUDENT) ==========
    if (path === '/api/bookings/student' && request.method === 'GET') {
      const user = await getCurrentUser(request, env);
      if (!user) {
        return new Response(JSON.stringify({ success: false, message: 'Unauthorized' }), 
          { status: 401, headers: corsHeaders });
      }
      
      const bookings = await env.DB.prepare(`
        SELECT b.*, u.name as tutor_name, u.email as tutor_email 
        FROM bookings b 
        JOIN users u ON b.tutor_id = u.id 
        WHERE b.student_id = ?
        ORDER BY b.date DESC, b.time DESC
      `).bind(user.id).all();
      
      return new Response(JSON.stringify({ success: true, bookings: bookings.results }), { headers: corsHeaders });
    }

    // ========== GET BOOKINGS (PROFESSOR) ==========
    if (path === '/api/bookings/professor' && request.method === 'GET') {
      const user = await getCurrentUser(request, env);
      if (!user || user.role !== 'professor') {
        return new Response(JSON.stringify({ success: false, message: 'Unauthorized' }), 
          { status: 401, headers: corsHeaders });
      }
      
      const bookings = await env.DB.prepare(`
        SELECT b.*, u.name as student_name, u.email as student_email 
        FROM bookings b 
        JOIN users u ON b.student_id = u.id 
        WHERE b.tutor_id = ? AND b.status = 'pending'
        ORDER BY b.date DESC, b.time DESC
      `).bind(user.id).all();
      
      return new Response(JSON.stringify({ success: true, bookings: bookings.results }), { headers: corsHeaders });
    }

    // ========== ACCEPT BOOKING ==========
    if (path === '/api/bookings/accept' && request.method === 'POST') {
      const user = await getCurrentUser(request, env);
      if (!user || user.role !== 'professor') {
        return new Response(JSON.stringify({ success: false, message: 'Unauthorized' }), 
          { status: 401, headers: corsHeaders });
      }
      
      const body = await request.json();
      await env.DB.prepare('UPDATE bookings SET status = ? WHERE id = ? AND tutor_id = ?')
        .bind('accepted', body.booking_id, user.id).run();
      
      return new Response(JSON.stringify({ success: true, message: 'Booking accepted' }), { headers: corsHeaders });
    }

    // ========== REJECT BOOKING ==========
    if (path === '/api/bookings/reject' && request.method === 'POST') {
      const user = await getCurrentUser(request, env);
      if (!user || user.role !== 'professor') {
        return new Response(JSON.stringify({ success: false, message: 'Unauthorized' }), 
          { status: 401, headers: corsHeaders });
      }
      
      const body = await request.json();
      await env.DB.prepare('UPDATE bookings SET status = ? WHERE id = ? AND tutor_id = ?')
        .bind('rejected', body.booking_id, user.id).run();
      
      return new Response(JSON.stringify({ success: true, message: 'Booking rejected' }), { headers: corsHeaders });
    }

    // 404 Not Found
    return new Response(JSON.stringify({ success: false, message: 'Not found' }), 
      { status: 404, headers: corsHeaders });

  } catch (error: any) {
    console.error('API Error:', error);
    return new Response(JSON.stringify({ success: false, message: error.message || 'Internal server error' }), 
      { status: 500, headers: corsHeaders });
  }
}