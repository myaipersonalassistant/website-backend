const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize Firebase Admin
// Check if already initialized to avoid re-initialization errors
if (admin.apps.length === 0) {
  try {
    // Option 1: Using service account JSON string (FIREBASE_SERVICE_ACCOUNT or FIREBASE_SERVICE_ACCOUNT_KEY)
    const serviceAccountEnv = process.env.FIREBASE_SERVICE_ACCOUNT || process.env.FIREBASE_SERVICE_ACCOUNT_KEY;
    
    if (serviceAccountEnv) {
      // Parse service account from environment variable (JSON string)
      const serviceAccount = JSON.parse(serviceAccountEnv);
      
      // Fix private key newlines - replace literal \n strings with actual newlines
      if (serviceAccount.private_key) {
        serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
      }
      
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        projectId: process.env.FIREBASE_PROJECT_ID || serviceAccount.project_id,
      });
      console.log('✅ Firebase Admin initialized using service account from environment variable');
    } 
    // Option 2: Using service account file path
    else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
      const serviceAccount = require(process.env.GOOGLE_APPLICATION_CREDENTIALS);
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        projectId: process.env.FIREBASE_PROJECT_ID || serviceAccount.project_id,
      });
      console.log('✅ Firebase Admin initialized using service account file');
    }
    // Option 3: Using individual environment variables
    else if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_PRIVATE_KEY && process.env.FIREBASE_CLIENT_EMAIL) {
      // Fix private key newlines - replace literal \n with actual newlines
      let privateKey = process.env.FIREBASE_PRIVATE_KEY;
      
      // Remove surrounding quotes if present
      if ((privateKey.startsWith('"') && privateKey.endsWith('"')) || 
          (privateKey.startsWith("'") && privateKey.endsWith("'"))) {
        privateKey = privateKey.slice(1, -1);
      }
      
      // Replace literal \n with actual newlines
      privateKey = privateKey.replace(/\\n/g, '\n');
      
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId: process.env.FIREBASE_PROJECT_ID,
          privateKey: privateKey,
          clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        })
      });
      console.log('✅ Firebase Admin initialized using individual env variables');
    }
    // Option 4: Using default credentials (for Firebase hosting/Cloud Run)
    else if (process.env.FIREBASE_PROJECT_ID) {
      admin.initializeApp({
        projectId: process.env.FIREBASE_PROJECT_ID,
      });
      console.log('✅ Firebase Admin initialized using default credentials with project ID');
    }
    // Option 5: Try default initialization
    else {
      admin.initializeApp();
      console.log('✅ Firebase Admin initialized using default credentials');
    }
  } catch (error) {
    console.error('❌ Error initializing Firebase:', error.message);
    console.error('💡 Make sure you have set one of the following:');
    console.error('   - FIREBASE_SERVICE_ACCOUNT (JSON string)');
    console.error('   - FIREBASE_SERVICE_ACCOUNT_KEY (JSON string, legacy)');
    console.error('   - GOOGLE_APPLICATION_CREDENTIALS (file path)');
    console.error('   - FIREBASE_PROJECT_ID with FIREBASE_PRIVATE_KEY and FIREBASE_CLIENT_EMAIL');
    throw error;
  }
} else {
  console.log('✅ Firebase Admin already initialized');
}

// Initialize Firestore
const db = admin.firestore();

// ============================================
// API USAGE TRACKING & RATE LIMITING
// ============================================
// Using in-memory storage to avoid Firestore read/write costs

// In-memory storage for API usage (no Firestore writes)
const apiUsageStore = {
  // Recent activity (last 1000 requests) - for admin activity log
  recentActivity: [],
  
  // Daily usage counters: userId -> { deepseek: count, elevenlabs: count, date: 'YYYY-MM-DD' }
  dailyUsage: new Map(),
  
  // Monthly usage counters: userId -> { deepseek: count, elevenlabs: count, month: 'YYYY-MM' }
  monthlyUsage: new Map(),
  
  // User summaries: userId -> { deepseekRequests, elevenlabsRequests, totalRequests, costs, etc. }
  userSummaries: new Map(),
  
  // Max recent activity to keep (to prevent memory bloat)
  MAX_RECENT_ACTIVITY: 1000
};

// Cleanup old daily usage data (older than 2 days)
function cleanupOldDailyUsage() {
  const twoDaysAgo = new Date();
  twoDaysAgo.setDate(twoDaysAgo.getDate() - 2);
  const cutoffDate = twoDaysAgo.toISOString().split('T')[0];
  
  for (const [key, data] of apiUsageStore.dailyUsage.entries()) {
    if (data.date < cutoffDate) {
      apiUsageStore.dailyUsage.delete(key);
    }
  }
}

// Cleanup old monthly usage data (older than 2 months)
function cleanupOldMonthlyUsage() {
  const twoMonthsAgo = new Date();
  twoMonthsAgo.setMonth(twoMonthsAgo.getMonth() - 2);
  const cutoffMonth = `${twoMonthsAgo.getFullYear()}-${String(twoMonthsAgo.getMonth() + 1).padStart(2, '0')}`;
  
  for (const [key, data] of apiUsageStore.monthlyUsage.entries()) {
    if (data.month < cutoffMonth) {
      apiUsageStore.monthlyUsage.delete(key);
    }
  }
}

// Cleanup old recent activity (keep only last MAX_RECENT_ACTIVITY)
function cleanupRecentActivity() {
  if (apiUsageStore.recentActivity.length > apiUsageStore.MAX_RECENT_ACTIVITY) {
    apiUsageStore.recentActivity = apiUsageStore.recentActivity.slice(-apiUsageStore.MAX_RECENT_ACTIVITY);
  }
}

// Run cleanup every hour
setInterval(() => {
  cleanupOldDailyUsage();
  cleanupOldMonthlyUsage();
  cleanupRecentActivity();
}, 60 * 60 * 1000);

// Rate limit configuration per plan
const RATE_LIMITS = {
  student: {
    deepseek: { daily: 100, monthly: 2000 },
    elevenlabs: { daily: 50, monthly: 1000 },
    costPerDeepseek: 0.001,
    costPerElevenlabs: 0.003
  },
  professional: {
    deepseek: { daily: 500, monthly: 10000 },
    elevenlabs: { daily: 200, monthly: 5000 },
    costPerDeepseek: 0.001,
    costPerElevenlabs: 0.003
  },
  executive: {
    deepseek: { daily: 2000, monthly: 50000 },
    elevenlabs: { daily: 1000, monthly: 25000 },
    costPerDeepseek: 0.001,
    costPerElevenlabs: 0.003
  },
  team: {
    deepseek: { daily: 5000, monthly: 100000 },
    elevenlabs: { daily: 2500, monthly: 50000 },
    costPerDeepseek: 0.001,
    costPerElevenlabs: 0.003
  }
};

// Helper function to get user's plan
async function getUserPlan(userId) {
  try {
    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists) {
      return 'student'; // Default plan
    }
    
    const userData = userDoc.data();
    // Check subscription subcollection
    const subscriptionRef = db.collection('users').doc(userId).collection('subscription').doc('current');
    const subscriptionDoc = await subscriptionRef.get();
    
    if (subscriptionDoc.exists) {
      const subData = subscriptionDoc.data();
      return subData.planId || subData.plan_id || 'student';
    }
    
    // Fallback to user document
    if (userData.subscription) {
      return userData.subscription.planId || userData.subscription.plan_id || 'student';
    }
    
    return 'student';
  } catch (error) {
    console.error('Error getting user plan:', error);
    return 'student';
  }
}

// Helper function to check rate limits (using in-memory storage)
async function checkRateLimit(userId, apiType) {
  try {
    const planId = await getUserPlan(userId);
    const limits = RATE_LIMITS[planId] || RATE_LIMITS.student;
    const apiLimits = limits[apiType] || limits.deepseek;
    
    const now = new Date();
    const todayDate = now.toISOString().split('T')[0]; // YYYY-MM-DD
    const monthDate = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`; // YYYY-MM
    
    // Get daily usage from memory
    const dailyKey = `${userId}_${apiType}_${todayDate}`;
    const dailyData = apiUsageStore.dailyUsage.get(dailyKey);
    const dailyCount = dailyData ? dailyData.count : 0;
    
    // Get monthly usage from memory
    const monthlyKey = `${userId}_${apiType}_${monthDate}`;
    const monthlyData = apiUsageStore.monthlyUsage.get(monthlyKey);
    const monthlyCount = monthlyData ? monthlyData.count : 0;
    
    const dailyExceeded = dailyCount >= apiLimits.daily;
    const monthlyExceeded = monthlyCount >= apiLimits.monthly;
    
    return {
      allowed: !dailyExceeded && !monthlyExceeded,
      dailyExceeded,
      monthlyExceeded,
      dailyCount,
      monthlyCount,
      dailyLimit: apiLimits.daily,
      monthlyLimit: apiLimits.monthly,
      planId
    };
  } catch (error) {
    console.error('Error checking rate limit:', error);
    // On error, allow the request but log it
    return {
      allowed: true,
      dailyExceeded: false,
      monthlyExceeded: false,
      dailyCount: 0,
      monthlyCount: 0,
      dailyLimit: 100,
      monthlyLimit: 2000,
      planId: 'student',
      error: error.message
    };
  }
}

// Helper function to record API usage (in-memory only, no Firestore)
async function recordAPIUsage(userId, apiType, success, blocked, rateLimitExceeded, responseTime, requestSize) {
  try {
    const planId = await getUserPlan(userId);
    const limits = RATE_LIMITS[planId] || RATE_LIMITS.student;
    const cost = apiType === 'deepseek' ? limits.costPerDeepseek : limits.costPerElevenlabs;
    
    const now = new Date();
    const timestamp = now.toISOString();
    const todayDate = now.toISOString().split('T')[0]; // YYYY-MM-DD
    const monthDate = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`; // YYYY-MM
    
    // Add to recent activity (for admin activity log)
    const activityRecord = {
      id: `${userId}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      userId,
      apiType,
      timestamp,
      cost,
      success,
      blocked,
      rateLimitExceeded,
      planId,
      requestSize: requestSize || null,
      responseTime: responseTime || null
    };
    
    apiUsageStore.recentActivity.push(activityRecord);
    cleanupRecentActivity();
    
    // Update daily usage counter
    const dailyKey = `${userId}_${apiType}_${todayDate}`;
    const dailyData = apiUsageStore.dailyUsage.get(dailyKey);
    if (dailyData) {
      dailyData.count++;
      dailyData.cost += cost;
    } else {
      apiUsageStore.dailyUsage.set(dailyKey, {
        userId,
        apiType,
        date: todayDate,
        count: 1,
        cost
      });
    }
    
    // Update monthly usage counter
    const monthlyKey = `${userId}_${apiType}_${monthDate}`;
    const monthlyData = apiUsageStore.monthlyUsage.get(monthlyKey);
    if (monthlyData) {
      monthlyData.count++;
      monthlyData.cost += cost;
    } else {
      apiUsageStore.monthlyUsage.set(monthlyKey, {
        userId,
        apiType,
        month: monthDate,
        count: 1,
        cost
      });
    }
    
    // Update user summary
    const userSummary = apiUsageStore.userSummaries.get(userId) || {
      userId,
      planId,
      deepseekRequests: 0,
      elevenlabsRequests: 0,
      totalRequests: 0,
      deepseekCost: 0,
      elevenlabsCost: 0,
      totalCost: 0,
      rateLimitHits: 0,
      blockedRequests: 0,
      lastRequestAt: null
    };
    
    if (apiType === 'deepseek') {
      userSummary.deepseekRequests++;
      userSummary.deepseekCost += cost;
    } else {
      userSummary.elevenlabsRequests++;
      userSummary.elevenlabsCost += cost;
    }
    
    userSummary.totalRequests++;
    userSummary.totalCost += cost;
    userSummary.lastRequestAt = timestamp;
    
    if (rateLimitExceeded) {
      userSummary.rateLimitHits++;
    }
    if (blocked) {
      userSummary.blockedRequests++;
    }
    
    apiUsageStore.userSummaries.set(userId, userSummary);
  } catch (error) {
    console.error('Error recording API usage:', error);
    // Don't throw - usage tracking shouldn't break the API
  }
}

// Middleware to check rate limits and track usage
async function rateLimitMiddleware(req, res, next) {
  const userId = req.user.uid;
  const apiType = req.apiType || 'deepseek'; // Set by route
  
  try {
    const rateLimitCheck = await checkRateLimit(userId, apiType);
    
    if (!rateLimitCheck.allowed) {
      // Record blocked request
      await recordAPIUsage(userId, apiType, false, true, true, null, null);
      
      return res.status(429).json({
        error: 'Rate limit exceeded',
        message: rateLimitCheck.dailyExceeded 
          ? `Daily limit of ${rateLimitCheck.dailyLimit} requests exceeded. You have used ${rateLimitCheck.dailyCount} requests today.`
          : `Monthly limit of ${rateLimitCheck.monthlyLimit} requests exceeded. You have used ${rateLimitCheck.monthlyCount} requests this month.`,
        limit: rateLimitCheck.dailyExceeded ? rateLimitCheck.dailyLimit : rateLimitCheck.monthlyLimit,
        used: rateLimitCheck.dailyExceeded ? rateLimitCheck.dailyCount : rateLimitCheck.monthlyCount,
        planId: rateLimitCheck.planId,
        resetTime: rateLimitCheck.dailyExceeded 
          ? new Date(new Date().setHours(24, 0, 0, 0)).toISOString()
          : new Date(new Date().getFullYear(), new Date().getMonth() + 1, 1).toISOString()
      });
    }
    
    // Attach rate limit info to request
    req.rateLimitInfo = rateLimitCheck;
    next();
  } catch (error) {
    console.error('Error in rate limit middleware:', error);
    // On error, allow the request but log it
    next();
  }
}

// ============================================
// AUTHENTICATION MIDDLEWARE
// ============================================

/**
 * Verify Firebase ID token and attach user info to request
 */
async function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        error: 'Unauthorized',
        message: 'No token provided' 
      });
    }

    const token = authHeader.split('Bearer ')[1];
    const decodedToken = await admin.auth().verifyIdToken(token);
    
    req.user = {
      uid: decodedToken.uid,
      email: decodedToken.email,
      ...decodedToken
    };
    
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(401).json({ 
      error: 'Unauthorized',
      message: 'Invalid or expired token' 
    });
  }
}

// ============================================
// NOTIFICATIONS ROUTES (Firestore)
// ============================================

/**
 * Helper function to handle Firestore index errors
 */
function handleFirestoreError(error, res) {
  // Check if it's a Firestore index error (code 9 = FAILED_PRECONDITION)
  if (error.code === 9 || (error.message && error.message.includes('index'))) {
    const indexUrl = error.details || error.message?.match(/https:\/\/[^\s]+/)?.[0];
    return res.status(400).json({ 
      error: 'Firestore index required',
      message: 'This query requires a Firestore composite index. Please create it using the link below.',
      indexUrl: indexUrl || 'https://console.firebase.google.com/project/aipersonalassistant-8q4k9a/firestore/indexes',
      instructions: 'Click the indexUrl to create the required index, then wait a few minutes for it to build.'
    });
  }
  return null;
}

/**
 * GET /api/notifications
 * Fetch all notifications for the authenticated user
 */
app.get('/api/notifications', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const { showArchived = 'false' } = req.query;

    // Build Firestore query
    let notificationsRef = db.collection('notifications')
      .where('userId', '==', userId);

    // Filter by archived status
    if (showArchived !== 'true') {
      // Query with is_archived filter (requires index: userId, is_archived, created_at)
      notificationsRef = notificationsRef.where('is_archived', '==', false);
    }
    // When showArchived is true, we only filter by userId (requires index: userId, created_at)

    // Order by created_at descending and get results
    const snapshot = await notificationsRef
      .orderBy('created_at', 'desc')
      .get();

    const userNotifications = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      created_at: doc.data().created_at?.toDate?.()?.toISOString() || doc.data().created_at,
      read_at: doc.data().read_at?.toDate?.()?.toISOString() || doc.data().read_at,
      expires_at: doc.data().expires_at?.toDate?.()?.toISOString() || doc.data().expires_at,
    }));

    res.json({ notifications: userNotifications });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    
    // Handle Firestore index errors with helpful messages
    const indexError = handleFirestoreError(error, res);
    if (indexError) return indexError;
    
    res.status(500).json({ error: 'Failed to fetch notifications', message: error.message });
  }
});

/**
 * GET /api/notifications/unread-count
 * Get unread notification count for the authenticated user (for header badge)
 */
app.get('/api/notifications/unread-count', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    
    const snapshot = await db.collection('notifications')
      .where('userId', '==', userId)
      .where('is_read', '==', false)
      .where('is_archived', '==', false)
      .get();

    res.json({ unreadCount: snapshot.size });
  } catch (error) {
    console.error('Error fetching unread count:', error);
    const indexError = handleFirestoreError(error, res);
    if (indexError) return indexError;
    res.status(500).json({ error: 'Failed to fetch unread count', message: error.message });
  }
});

/**
 * GET /api/notifications/recent
 * Get recent notifications (for header dropdown - limited to 5)
 */
app.get('/api/notifications/recent', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const limit = parseInt(req.query.limit) || 5;

    const snapshot = await db.collection('notifications')
      .where('userId', '==', userId)
      .where('is_archived', '==', false)
      .orderBy('created_at', 'desc')
      .limit(limit)
      .get();

    const userNotifications = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      created_at: doc.data().created_at?.toDate?.()?.toISOString() || doc.data().created_at,
      read_at: doc.data().read_at?.toDate?.()?.toISOString() || doc.data().read_at,
    }));

    res.json({ notifications: userNotifications });
  } catch (error) {
    console.error('Error fetching recent notifications:', error);
    const indexError = handleFirestoreError(error, res);
    if (indexError) return indexError;
    res.status(500).json({ error: 'Failed to fetch recent notifications', message: error.message });
  }
});

/**
 * PATCH /api/notifications/:id
 * Update a specific notification
 */
app.patch('/api/notifications/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.uid;
    const updates = req.body;

    const notificationRef = db.collection('notifications').doc(id);
    const notificationDoc = await notificationRef.get();

    if (!notificationDoc.exists) {
      return res.status(404).json({ error: 'Notification not found' });
    }

    const notificationData = notificationDoc.data();
    if (notificationData.userId !== userId) {
      return res.status(403).json({ error: 'Forbidden', message: 'You do not have permission to update this notification' });
    }

    // Prepare update data
    const updateData = {
      ...updates,
      updated_at: admin.firestore.FieldValue.serverTimestamp()
    };

    // Convert date strings to Timestamp if needed
    if (updates.read_at && typeof updates.read_at === 'string') {
      updateData.read_at = admin.firestore.Timestamp.fromDate(new Date(updates.read_at));
    }
    if (updates.expires_at && typeof updates.expires_at === 'string') {
      updateData.expires_at = admin.firestore.Timestamp.fromDate(new Date(updates.expires_at));
    }

    await notificationRef.update(updateData);

    // Get updated notification
    const updatedDoc = await notificationRef.get();
    const updatedNotification = {
      id: updatedDoc.id,
      ...updatedDoc.data(),
      created_at: updatedDoc.data().created_at?.toDate?.()?.toISOString() || updatedDoc.data().created_at,
      read_at: updatedDoc.data().read_at?.toDate?.()?.toISOString() || updatedDoc.data().read_at,
      expires_at: updatedDoc.data().expires_at?.toDate?.()?.toISOString() || updatedDoc.data().expires_at,
    };

    res.json({ 
      success: true, 
      notification: updatedNotification 
    });
  } catch (error) {
    console.error('Error updating notification:', error);
    res.status(500).json({ error: 'Failed to update notification', message: error.message });
  }
});

/**
 * POST /api/notifications/mark-all-read
 * Mark all notifications as read for the authenticated user
 */
app.post('/api/notifications/mark-all-read', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const now = admin.firestore.Timestamp.now();

    // Get all unread notifications
    const snapshot = await db.collection('notifications')
      .where('userId', '==', userId)
      .where('is_read', '==', false)
      .get();

    // Batch update
    const batch = db.batch();
    snapshot.docs.forEach(doc => {
      batch.update(doc.ref, {
        is_read: true,
        read_at: now,
        updated_at: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    await batch.commit();

    res.json({ success: true, updatedCount: snapshot.size });
  } catch (error) {
    console.error('Error marking all as read:', error);
    res.status(500).json({ error: 'Failed to mark all as read', message: error.message });
  }
});

/**
 * DELETE /api/notifications/:id
 * Delete a specific notification
 */
app.delete('/api/notifications/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.uid;

    const notificationRef = db.collection('notifications').doc(id);
    const notificationDoc = await notificationRef.get();

    if (!notificationDoc.exists) {
      return res.status(404).json({ error: 'Notification not found' });
    }

    const notificationData = notificationDoc.data();
    if (notificationData.userId !== userId) {
      return res.status(403).json({ error: 'Forbidden', message: 'You do not have permission to delete this notification' });
    }

    await notificationRef.delete();

    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting notification:', error);
    res.status(500).json({ error: 'Failed to delete notification', message: error.message });
  }
});

/**
 * POST /api/notifications
 * Create a new notification (for system use)
 */
app.post('/api/notifications', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const {
      title,
      message,
      type = 'info',
      category = 'general',
      priority = 'medium',
      action_url,
      metadata,
      expires_at
    } = req.body;

    const notificationData = {
      userId,
      title,
      message,
      type,
      category,
      priority,
      is_read: false,
      is_archived: false,
      action_url: action_url || null,
      metadata: metadata || {},
      created_at: admin.firestore.FieldValue.serverTimestamp(),
      expires_at: expires_at ? admin.firestore.Timestamp.fromDate(new Date(expires_at)) : null
    };

    const docRef = await db.collection('notifications').add(notificationData);
    const doc = await docRef.get();
    
    const notification = {
      id: doc.id,
      ...doc.data(),
      created_at: doc.data().created_at?.toDate?.()?.toISOString() || doc.data().created_at,
      expires_at: doc.data().expires_at?.toDate?.()?.toISOString() || doc.data().expires_at,
    };

    res.status(201).json({ success: true, notification });
  } catch (error) {
    console.error('Error creating notification:', error);
    res.status(500).json({ error: 'Failed to create notification', message: error.message });
  }
});

// ============================================
// CALENDAR ROUTES
// ============================================

/**
 * GET /api/calendar/events
 * Fetch calendar events for a date range
 */
app.get('/api/calendar/events', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const { startDate, endDate, status } = req.query;

    let query = db.collection('events').where('userId', '==', userId);

    if (startDate) {
      const startTimestamp = admin.firestore.Timestamp.fromDate(new Date(startDate));
      query = query.where('start_time', '>=', startTimestamp);
    }
    if (endDate) {
      const endTimestamp = admin.firestore.Timestamp.fromDate(new Date(endDate));
      query = query.where('start_time', '<=', endTimestamp);
    }

    const snapshot = await query.get();
    let userEvents = snapshot.docs.map(doc => {
      const data = doc.data();
      return {
        id: doc.id,
        ...data,
        start_time: data.start_time?.toDate?.()?.toISOString() || data.start_time,
        end_time: data.end_time?.toDate?.()?.toISOString() || data.end_time,
        created_at: data.created_at?.toDate?.()?.toISOString() || data.created_at
      };
    });

    if (status) {
      userEvents = userEvents.filter(e => e.status === status);
    }

    userEvents.sort((a, b) => new Date(a.start_time) - new Date(b.start_time));

    res.json({ events: userEvents });
  } catch (error) {
    console.error('Error fetching events:', error);
    const errorResponse = handleFirestoreError(error, res);
    if (!errorResponse) {
      res.status(500).json({ error: 'Failed to fetch events', message: error.message });
    }
  }
});

/**
 * GET /api/calendar/activities/:date
 * Fetch all activities (events, reminders, tasks) for a specific date
 */
app.get('/api/calendar/activities/:date', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const { date } = req.params;

    const targetDate = new Date(date);
    const nextDate = new Date(targetDate);
    nextDate.setDate(nextDate.getDate() + 1);

    // Convert to Firestore Timestamps for querying
    const targetTimestamp = admin.firestore.Timestamp.fromDate(targetDate);
    const nextTimestamp = admin.firestore.Timestamp.fromDate(nextDate);

    // Track index URLs for any missing indexes
    const indexUrls = {
      events: null,
      reminders: null,
      tasks: null,
      emails: null
    };

    // Helper function to extract index URL from error
    const extractIndexUrl = (error) => {
      if (error.details) {
        const urlMatch = error.details.match(/https:\/\/[^\s\)]+/);
        if (urlMatch) return urlMatch[0];
      }
      if (error.message) {
        const urlMatch = error.message.match(/https:\/\/[^\s\)]+/);
        if (urlMatch) return urlMatch[0];
        // Also check for create_composite parameter
        const compositeMatch = error.message.match(/create_composite=[^\s\)]+/);
        if (compositeMatch) {
          return `https://console.firebase.google.com/v1/r/project/aipersonalassistant-8q4k9a/firestore/indexes?${compositeMatch[0]}`;
        }
      }
      return null;
    };

    // Get events for the date from Firestore
    let events = [];
    try {
      const eventsSnapshot = await db.collection('events')
        .where('userId', '==', userId)
        .where('start_time', '>=', targetTimestamp)
        .where('start_time', '<', nextTimestamp)
        .get();
      
      events = eventsSnapshot.docs.map(doc => {
        const data = doc.data();
        return {
          id: doc.id,
          ...data,
          start_time: data.start_time?.toDate?.()?.toISOString() || data.start_time,
          end_time: data.end_time?.toDate?.()?.toISOString() || data.end_time,
          created_at: data.created_at?.toDate?.()?.toISOString() || data.created_at
        };
      });
    } catch (error) {
      // Check if it's an index error (code 9 = FAILED_PRECONDITION)
      if (error.code === 9 || (error.message && error.message.includes('index'))) {
        console.log('Index missing for events query, using fallback (client-side filtering)');
        indexUrls.events = extractIndexUrl(error);
        // If query fails (e.g., missing index), fetch all and filter client-side
        const allEventsSnapshot = await db.collection('events')
          .where('userId', '==', userId)
          .get();
        
        events = allEventsSnapshot.docs
          .map(doc => {
            const data = doc.data();
            const startTime = data.start_time?.toDate?.() || new Date(data.start_time);
            return {
              id: doc.id,
              ...data,
              start_time: startTime.toISOString(),
              end_time: data.end_time?.toDate?.()?.toISOString() || data.end_time,
              created_at: data.created_at?.toDate?.()?.toISOString() || data.created_at
            };
          })
          .filter(e => {
            const eventDate = new Date(e.start_time);
            return eventDate >= targetDate && eventDate < nextDate;
          });
      } else {
        // For other errors, log and set empty array
        console.error('Error fetching events:', error);
        events = [];
      }
    }

    // Get reminders for the date from Firestore
    let remindersForDate = [];
    try {
      const remindersSnapshot = await db.collection('reminders')
        .where('userId', '==', userId)
        .where('remind_at', '>=', targetTimestamp)
        .where('remind_at', '<', nextTimestamp)
        .get();
      
      remindersForDate = remindersSnapshot.docs.map(doc => {
        const data = doc.data();
        return {
          id: doc.id,
          ...data,
          remind_at: data.remind_at?.toDate?.()?.toISOString() || data.remind_at,
          created_at: data.created_at?.toDate?.()?.toISOString() || data.created_at
        };
      });
    } catch (error) {
      // Check if it's an index error (code 9 = FAILED_PRECONDITION)
      if (error.code === 9 || (error.message && error.message.includes('index'))) {
        console.log('Index missing for reminders query, using fallback (client-side filtering)');
        indexUrls.reminders = extractIndexUrl(error);
        const allRemindersSnapshot = await db.collection('reminders')
          .where('userId', '==', userId)
          .get();
        
        remindersForDate = allRemindersSnapshot.docs
          .map(doc => {
            const data = doc.data();
            const remindAt = data.remind_at?.toDate?.() || new Date(data.remind_at);
            return {
              id: doc.id,
              ...data,
              remind_at: remindAt.toISOString(),
              created_at: data.created_at?.toDate?.()?.toISOString() || data.created_at
            };
          })
          .filter(r => {
            const reminderDate = new Date(r.remind_at);
            return reminderDate >= targetDate && reminderDate < nextDate;
          });
      } else {
        // For other errors, log and set empty array
        console.error('Error fetching reminders:', error);
        remindersForDate = [];
      }
    }

    // Get tasks for the date from Firestore
    let tasksForDate = [];
    try {
      const tasksSnapshot = await db.collection('tasks')
        .where('userId', '==', userId)
        .where('due_date', '>=', targetTimestamp)
        .where('due_date', '<', nextTimestamp)
        .get();
      
      tasksForDate = tasksSnapshot.docs
        .map(doc => {
          const data = doc.data();
          return {
            id: doc.id,
            ...data,
            due_date: data.due_date?.toDate?.()?.toISOString() || data.due_date,
            created_at: data.created_at?.toDate?.()?.toISOString() || data.created_at
          };
        })
        .filter(t => t.due_date); // Only tasks with due_date
    } catch (error) {
      // Check if it's an index error (code 9 = FAILED_PRECONDITION)
      if (error.code === 9 || (error.message && error.message.includes('index'))) {
        console.log('Index missing for tasks query, using fallback (client-side filtering)');
        indexUrls.tasks = extractIndexUrl(error);
        const allTasksSnapshot = await db.collection('tasks')
          .where('userId', '==', userId)
          .get();
        
        tasksForDate = allTasksSnapshot.docs
          .map(doc => {
            const data = doc.data();
            const dueDate = data.due_date?.toDate?.() || (data.due_date ? new Date(data.due_date) : null);
            return {
              id: doc.id,
              ...data,
              due_date: dueDate?.toISOString() || data.due_date,
              created_at: data.created_at?.toDate?.()?.toISOString() || data.created_at
            };
          })
          .filter(t => {
            if (!t.due_date) return false;
            const taskDate = new Date(t.due_date);
            return taskDate >= targetDate && taskDate < nextDate;
          });
      } else {
        // For other errors, log and set empty array
        console.error('Error fetching tasks:', error);
        tasksForDate = [];
      }
    }

    // Get email insights for the date from Firestore
    let emailInsights = [];
    try {
      const emailsSnapshot = await db.collection('emails')
        .where('userId', '==', userId)
        .where('received_at', '>=', targetTimestamp)
        .where('received_at', '<', nextTimestamp)
        .get();
      
      const emailIds = emailsSnapshot.docs.map(doc => doc.id);
      
      // Get extracted items count for each email
      const itemsCounts = {};
      if (emailIds.length > 0) {
        const itemsSnapshot = await db.collection('extracted_items')
          .where('userId', '==', userId)
          .where('email_id', 'in', emailIds.length > 10 ? emailIds.slice(0, 10) : emailIds)
          .get();
        
        itemsSnapshot.docs.forEach(doc => {
          const emailId = doc.data().email_id;
          if (!itemsCounts[emailId]) itemsCounts[emailId] = 0;
          itemsCounts[emailId]++;
        });
      }
      
      emailInsights = emailsSnapshot.docs.map(doc => {
        const data = doc.data();
        return {
          id: doc.id,
          email_id: doc.id,
          subject: data.subject || '',
          from_name: data.from_name || '',
          from_email: data.from_email || '',
          received_at: data.received_at?.toDate?.()?.toISOString() || data.received_at,
          items_count: itemsCounts[doc.id] || 0
        };
      });
    } catch (error) {
      // Check if it's an index error (code 9 = FAILED_PRECONDITION)
      if (error.code === 9 || (error.message && error.message.includes('index'))) {
        console.log('Index missing for emails query, using fallback (client-side filtering)');
        indexUrls.emails = extractIndexUrl(error);
        // Fallback: fetch all emails and filter client-side
        const allEmailsSnapshot = await db.collection('emails')
          .where('userId', '==', userId)
          .get();
        
        const emailIds = allEmailsSnapshot.docs.map(doc => doc.id);
        const itemsCounts = {};
        
        if (emailIds.length > 0) {
          // Fetch in batches if needed
          for (let i = 0; i < emailIds.length; i += 10) {
            const batch = emailIds.slice(i, i + 10);
            const itemsSnapshot = await db.collection('extracted_items')
              .where('userId', '==', userId)
              .where('email_id', 'in', batch)
              .get();
            
            itemsSnapshot.docs.forEach(doc => {
              const emailId = doc.data().email_id;
              if (!itemsCounts[emailId]) itemsCounts[emailId] = 0;
              itemsCounts[emailId]++;
            });
          }
        }
        
        emailInsights = allEmailsSnapshot.docs
          .map(doc => {
            const data = doc.data();
            const receivedAt = data.received_at?.toDate?.() || new Date(data.received_at);
            return {
              id: doc.id,
              email_id: doc.id,
              subject: data.subject || '',
              from_name: data.from_name || '',
              from_email: data.from_email || '',
              received_at: receivedAt.toISOString(),
              items_count: itemsCounts[doc.id] || 0
            };
          })
          .filter(e => {
            const emailDate = new Date(e.received_at);
            return emailDate >= targetDate && emailDate < nextDate;
          });
      } else {
        // For other errors, log and set empty array
        console.error('Error fetching email insights:', error);
        emailInsights = [];
      }
    }

    // Check if any indexes are missing
    const missingIndexes = Object.entries(indexUrls).filter(([_, url]) => url !== null);
    
    res.json({
      date,
      events,
      reminders: remindersForDate,
      tasks: tasksForDate,
      emailInsights,
      ...(missingIndexes.length > 0 && {
        indexWarnings: missingIndexes.map(([collection, url]) => ({
          collection,
          indexUrl: url
        }))
      })
    });
  } catch (error) {
    console.error('Error fetching activities:', error);
    const errorResponse = handleFirestoreError(error, res);
    if (!errorResponse) {
      res.status(500).json({ error: 'Failed to fetch activities', message: error.message });
    }
  }
});

/**
 * POST /api/calendar/events
 * Create a new calendar event
 */
app.post('/api/calendar/events', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const {
      title,
      description,
      start_time,
      end_time,
      location,
      status = 'pending',
      source = 'manual'
    } = req.body;

    const eventData = {
      userId,
      title,
      description: description || '',
      start_time: admin.firestore.Timestamp.fromDate(new Date(start_time)),
      end_time: end_time ? admin.firestore.Timestamp.fromDate(new Date(end_time)) : null,
      location: location || '',
      status,
      source,
      created_at: admin.firestore.FieldValue.serverTimestamp()
    };

    const docRef = await db.collection('events').add(eventData);
    const eventDoc = await docRef.get();
    const event = {
      id: docRef.id,
      ...eventDoc.data(),
      start_time: eventDoc.data().start_time?.toDate?.()?.toISOString() || start_time,
      end_time: eventDoc.data().end_time?.toDate?.()?.toISOString() || end_time,
      created_at: eventDoc.data().created_at?.toDate?.()?.toISOString() || new Date().toISOString()
    };

    res.status(201).json({ success: true, event });
  } catch (error) {
    console.error('Error creating event:', error);
    res.status(500).json({ error: 'Failed to create event', message: error.message });
  }
});

/**
 * PATCH /api/calendar/events/:id
 * Update a calendar event
 */
app.patch('/api/calendar/events/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.uid;
    const updates = req.body;

    const eventRef = db.collection('events').doc(id);
    const eventDoc = await eventRef.get();

    if (!eventDoc.exists) {
      return res.status(404).json({ error: 'Event not found' });
    }

    const eventData = eventDoc.data();
    if (eventData.userId !== userId) {
      return res.status(403).json({ error: 'Forbidden', message: 'You can only update your own events' });
    }

    // Convert date strings to Firestore Timestamps if present
    const updateData = { ...updates };
    if (updates.start_time) {
      updateData.start_time = admin.firestore.Timestamp.fromDate(new Date(updates.start_time));
    }
    if (updates.end_time) {
      updateData.end_time = admin.firestore.Timestamp.fromDate(new Date(updates.end_time));
    }
    updateData.updated_at = admin.firestore.FieldValue.serverTimestamp();

    await eventRef.update(updateData);

    const updatedDoc = await eventRef.get();
    const event = {
      id: updatedDoc.id,
      ...updatedDoc.data(),
      start_time: updatedDoc.data().start_time?.toDate?.()?.toISOString() || updates.start_time,
      end_time: updatedDoc.data().end_time?.toDate?.()?.toISOString() || updates.end_time,
      updated_at: updatedDoc.data().updated_at?.toDate?.()?.toISOString() || new Date().toISOString()
    };

    res.json({ success: true, event });
  } catch (error) {
    console.error('Error updating event:', error);
    res.status(500).json({ error: 'Failed to update event', message: error.message });
  }
});

/**
 * DELETE /api/calendar/events/:id
 * Delete a calendar event
 */
app.delete('/api/calendar/events/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.uid;

    const eventRef = db.collection('events').doc(id);
    const eventDoc = await eventRef.get();

    if (!eventDoc.exists) {
      return res.status(404).json({ error: 'Event not found' });
    }

    const eventData = eventDoc.data();
    if (eventData.userId !== userId) {
      return res.status(403).json({ error: 'Forbidden', message: 'You can only delete your own events' });
    }

    await eventRef.delete();

    res.json({ success: true, message: 'Event deleted' });
  } catch (error) {
    console.error('Error deleting event:', error);
    res.status(500).json({ error: 'Failed to delete event', message: error.message });
  }
});

// ============================================
// REMINDERS ROUTES
// ============================================

/**
 * GET /api/reminders
 * Fetch reminders for the authenticated user
 */
app.get('/api/reminders', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const { status, startDate, endDate } = req.query;

    let userReminders = reminders.filter(r => r.userId === userId);

    if (status) {
      userReminders = userReminders.filter(r => r.status === status);
    }
    if (startDate) {
      userReminders = userReminders.filter(r => new Date(r.remind_at) >= new Date(startDate));
    }
    if (endDate) {
      userReminders = userReminders.filter(r => new Date(r.remind_at) <= new Date(endDate));
    }

    userReminders.sort((a, b) => new Date(a.remind_at) - new Date(b.remind_at));

    res.json({ reminders: userReminders });
  } catch (error) {
    console.error('Error fetching reminders:', error);
    res.status(500).json({ error: 'Failed to fetch reminders', message: error.message });
  }
});

/**
 * POST /api/reminders
 * Create a new reminder
 */
app.post('/api/reminders', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const {
      title,
      description,
      remind_at,
      status = 'pending',
      source = 'manual'
    } = req.body;

    const reminder = {
      id: `reminder_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      userId,
      title,
      description,
      remind_at,
      status,
      source,
      created_at: new Date().toISOString()
    };

    reminders.push(reminder);

    res.status(201).json({ success: true, reminder });
  } catch (error) {
    console.error('Error creating reminder:', error);
    res.status(500).json({ error: 'Failed to create reminder', message: error.message });
  }
});

/**
 * PATCH /api/reminders/:id
 * Update a reminder
 */
app.patch('/api/reminders/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.uid;
    const updates = req.body;

    const reminderIndex = reminders.findIndex(
      r => r.id === id && r.userId === userId
    );

    if (reminderIndex === -1) {
      return res.status(404).json({ error: 'Reminder not found' });
    }

    reminders[reminderIndex] = {
      ...reminders[reminderIndex],
      ...updates,
      updated_at: new Date().toISOString()
    };

    res.json({ success: true, reminder: reminders[reminderIndex] });
  } catch (error) {
    console.error('Error updating reminder:', error);
    res.status(500).json({ error: 'Failed to update reminder', message: error.message });
  }
});

/**
 * DELETE /api/reminders/:id
 * Delete a reminder
 */
app.delete('/api/reminders/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.uid;

    const reminderIndex = reminders.findIndex(
      r => r.id === id && r.userId === userId
    );

    if (reminderIndex === -1) {
      return res.status(404).json({ error: 'Reminder not found' });
    }

    reminders.splice(reminderIndex, 1);

    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting reminder:', error);
    res.status(500).json({ error: 'Failed to delete reminder', message: error.message });
  }
});

// ============================================
// TASKS ROUTES
// ============================================

/**
 * GET /api/tasks
 * Fetch tasks for the authenticated user
 */
app.get('/api/tasks', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const { status, priority, dueDate } = req.query;

    let userTasks = tasks.filter(t => t.userId === userId);

    if (status) {
      userTasks = userTasks.filter(t => t.status === status);
    }
    if (priority) {
      userTasks = userTasks.filter(t => t.priority === priority);
    }
    if (dueDate) {
      userTasks = userTasks.filter(t => {
        if (!t.due_date) return false;
        const taskDate = new Date(t.due_date);
        const filterDate = new Date(dueDate);
        return taskDate.toDateString() === filterDate.toDateString();
      });
    }

    userTasks.sort((a, b) => {
      if (a.due_date && b.due_date) {
        return new Date(a.due_date) - new Date(b.due_date);
      }
      return new Date(b.created_at) - new Date(a.created_at);
    });

    res.json({ tasks: userTasks });
  } catch (error) {
    console.error('Error fetching tasks:', error);
    res.status(500).json({ error: 'Failed to fetch tasks', message: error.message });
  }
});

/**
 * POST /api/tasks
 * Create a new task
 */
app.post('/api/tasks', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const {
      title,
      description,
      due_date,
      priority = 'normal',
      status = 'pending',
      source = 'manual'
    } = req.body;

    const task = {
      id: `task_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      userId,
      title,
      description,
      due_date,
      priority,
      status,
      source,
      created_at: new Date().toISOString()
    };

    tasks.push(task);

    res.status(201).json({ success: true, task });
  } catch (error) {
    console.error('Error creating task:', error);
    res.status(500).json({ error: 'Failed to create task', message: error.message });
  }
});

/**
 * PATCH /api/tasks/:id
 * Update a task
 */
app.patch('/api/tasks/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.uid;
    const updates = req.body;

    const taskIndex = tasks.findIndex(
      t => t.id === id && t.userId === userId
    );

    if (taskIndex === -1) {
      return res.status(404).json({ error: 'Task not found' });
    }

    tasks[taskIndex] = {
      ...tasks[taskIndex],
      ...updates,
      updated_at: new Date().toISOString()
    };

    res.json({ success: true, task: tasks[taskIndex] });
  } catch (error) {
    console.error('Error updating task:', error);
    res.status(500).json({ error: 'Failed to update task', message: error.message });
  }
});

/**
 * DELETE /api/tasks/:id
 * Delete a task
 */
app.delete('/api/tasks/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.uid;

    const taskIndex = tasks.findIndex(
      t => t.id === id && t.userId === userId
    );

    if (taskIndex === -1) {
      return res.status(404).json({ error: 'Task not found' });
    }

    tasks.splice(taskIndex, 1);

    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting task:', error);
    res.status(500).json({ error: 'Failed to delete task', message: error.message });
  }
});

// ============================================
// EMAIL INSIGHTS ROUTES
// ============================================

/**
 * GET /api/email-insights
 * Fetch email insights with extracted items
 */
app.get('/api/email-insights', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const { processed, type, status } = req.query;

    let userEmails = emails.filter(e => e.userId === userId);

    if (processed !== undefined) {
      userEmails = userEmails.filter(e => e.processed === (processed === 'true'));
    }

    // Attach extracted items to each email
    const emailsWithExtractions = userEmails.map(email => {
      const emailExtractedItems = extractedItems.filter(item => item.email_id === email.id);
      
      return {
        ...email,
        events: emailExtractedItems.filter(item => item.type === 'event'),
        reminders: emailExtractedItems.filter(item => item.type === 'reminder'),
        todos: emailExtractedItems.filter(item => item.type === 'todo')
      };
    });

    // Filter by type if provided
    if (type) {
      emailsWithExtractions.forEach(email => {
        if (type === 'events') {
          email.events = email.events.filter(e => !status || e.status === status);
        } else if (type === 'reminders') {
          email.reminders = email.reminders.filter(r => !status || r.status === status);
        } else if (type === 'tasks') {
          email.todos = email.todos.filter(t => !status || t.status === status);
        }
      });
    }

    emailsWithExtractions.sort((a, b) => new Date(b.received_at) - new Date(a.received_at));

    res.json({ emails: emailsWithExtractions });
  } catch (error) {
    console.error('Error fetching email insights:', error);
    res.status(500).json({ error: 'Failed to fetch email insights', message: error.message });
  }
});

/**
 * PATCH /api/email-insights/items/:id
 * Update an extracted item (event, reminder, or todo)
 */
app.patch('/api/email-insights/items/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.uid;
    const updates = req.body;

    const itemIndex = extractedItems.findIndex(
      item => item.id === id && item.userId === userId
    );

    if (itemIndex === -1) {
      return res.status(404).json({ error: 'Item not found' });
    }

    extractedItems[itemIndex] = {
      ...extractedItems[itemIndex],
      ...updates,
      updated_at: new Date().toISOString()
    };

    // If status is 'approved' and type is 'event', create calendar event
    if (updates.status === 'approved' && extractedItems[itemIndex].type === 'event') {
      const item = extractedItems[itemIndex];
      const event = {
        id: `event_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        userId,
        title: item.title,
        description: item.description,
        start_time: item.start_time,
        end_time: item.end_time,
        location: item.location,
        status: 'approved',
        source: 'email',
        email_id: item.email_id,
        created_at: new Date().toISOString()
      };
      // Save event to Firestore
      await db.collection('events').add({
        userId,
        title: item.title,
        description: item.description,
        start_time: admin.firestore.Timestamp.fromDate(new Date(item.start_time)),
        end_time: item.end_time ? admin.firestore.Timestamp.fromDate(new Date(item.end_time)) : null,
        location: item.location,
        status: 'approved',
        source: 'email',
        email_id: item.email_id,
        created_at: admin.firestore.FieldValue.serverTimestamp()
      });
    }

    // If status is 'approved' and type is 'reminder', create reminder
    if (updates.status === 'approved' && extractedItems[itemIndex].type === 'reminder') {
      const item = extractedItems[itemIndex];
      const reminder = {
        id: `reminder_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        userId,
        title: item.title,
        description: item.description,
        remind_at: item.remind_at,
        status: 'approved',
        source: 'email',
        email_id: item.email_id,
        created_at: new Date().toISOString()
      };
      reminders.push(reminder);
    }

    // If status is 'approved' and type is 'todo', create task
    if (updates.status === 'approved' && extractedItems[itemIndex].type === 'todo') {
      const item = extractedItems[itemIndex];
      const task = {
        id: `task_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        userId,
        title: item.title,
        description: item.description,
        due_date: item.due_date,
        priority: item.priority || 'normal',
        status: 'approved',
        source: 'email',
        email_id: item.email_id,
        created_at: new Date().toISOString()
      };
      tasks.push(task);
    }

    res.json({ success: true, item: extractedItems[itemIndex] });
  } catch (error) {
    console.error('Error updating extracted item:', error);
    res.status(500).json({ error: 'Failed to update item', message: error.message });
  }
});

/**
 * POST /api/email-insights/process
 * Process an email and extract items (for email processing service)
 */
app.post('/api/email-insights/process', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const {
      email_id,
      from_email,
      from_name,
      subject,
      content,
      received_at
    } = req.body;

    // Create email record
    const email = {
      id: email_id || `email_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      userId,
      from_email,
      from_name,
      subject,
      preview: content.substring(0, 200),
      content,
      received_at: received_at || new Date().toISOString(),
      processed: false,
      created_at: new Date().toISOString()
    };

    emails.push(email);

    // TODO: Integrate with AI service to extract events, reminders, and todos
    // For now, return the email with empty extractions
    res.status(201).json({ 
      success: true, 
      email,
      message: 'Email queued for processing' 
    });
  } catch (error) {
    console.error('Error processing email:', error);
    res.status(500).json({ error: 'Failed to process email', message: error.message });
  }
});

// ============================================
// DASHBOARD ROUTES
// ============================================

/**
 * GET /api/dashboard/stats
 * Get dashboard statistics
 */
app.get('/api/dashboard/stats', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const now = new Date();
    const tomorrow = new Date(now);
    tomorrow.setDate(tomorrow.getDate() + 1);

    // Get upcoming events from Firestore
    const nowTimestamp = admin.firestore.Timestamp.fromDate(now);
    const tomorrowTimestamp = admin.firestore.Timestamp.fromDate(tomorrow);
    
    let upcomingEvents = 0;
    try {
      const eventsSnapshot = await db.collection('events')
        .where('userId', '==', userId)
        .where('start_time', '>=', nowTimestamp)
        .where('start_time', '<=', tomorrowTimestamp)
        .get();
      
      upcomingEvents = eventsSnapshot.docs.filter(doc => {
        const data = doc.data();
        return data.status !== 'cancelled';
      }).length;
    } catch (error) {
      console.error('Error fetching upcoming events for dashboard:', error);
      // Fallback: fetch all and filter client-side
      const allEventsSnapshot = await db.collection('events')
        .where('userId', '==', userId)
        .get();
      
      upcomingEvents = allEventsSnapshot.docs.filter(doc => {
        const data = doc.data();
        if (data.status === 'cancelled') return false;
        const startTime = data.start_time?.toDate?.() || new Date(data.start_time);
        return startTime >= now && startTime <= tomorrow;
      }).length;
    }

    // Get pending tasks from Firestore
    let pendingTasks = 0;
    try {
      const tasksSnapshot = await db.collection('tasks')
        .where('userId', '==', userId)
        .where('status', 'in', ['pending', 'approved'])
        .get();
      pendingTasks = tasksSnapshot.size;
    } catch (error) {
      console.error('Error fetching pending tasks for dashboard:', error);
      // Fallback: fetch all and filter client-side
      const allTasksSnapshot = await db.collection('tasks')
        .where('userId', '==', userId)
        .get();
      pendingTasks = allTasksSnapshot.docs.filter(doc => {
        const data = doc.data();
        return data.status === 'pending' || data.status === 'approved';
      }).length;
    }

    // Get unprocessed emails from Firestore
    let unprocessedEmails = 0;
    try {
      const emailsSnapshot = await db.collection('emails')
        .where('userId', '==', userId)
        .where('processed', '==', false)
        .get();
      unprocessedEmails = emailsSnapshot.size;
    } catch (error) {
      console.error('Error fetching unprocessed emails for dashboard:', error);
      // Fallback: fetch all and filter client-side
      const allEmailsSnapshot = await db.collection('emails')
        .where('userId', '==', userId)
        .get();
      unprocessedEmails = allEmailsSnapshot.docs.filter(doc => {
        const data = doc.data();
        return !data.processed;
      }).length;
    }

    // Get unread notifications count from Firestore
    const unreadNotificationsSnapshot = await db.collection('notifications')
      .where('userId', '==', userId)
      .where('is_read', '==', false)
      .where('is_archived', '==', false)
      .get();
    const unreadNotifications = unreadNotificationsSnapshot.size;

    res.json({
      upcomingEvents,
      pendingTasks,
      unprocessedEmails,
      unreadNotifications
    });
  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard stats', message: error.message });
  }
});

// ============================================
// SERVICE CONNECTIONS ROUTES (OAuth)
// ============================================

/**
 * GET /api/services/connect/:serviceId
 * Initiate OAuth flow for a service (Gmail, Google Calendar, Zoom)
 */
app.get('/api/services/connect/:serviceId', verifyToken, async (req, res) => {
  try {
    const { serviceId } = req.params;
    const userId = req.user.uid;
    const { redirectUri } = req.query;

    const validServices = ['gmail', 'google-calendar', 'zoom'];
    if (!validServices.includes(serviceId)) {
      return res.status(400).json({ 
        error: 'Invalid service',
        message: `Service must be one of: ${validServices.join(', ')}` 
      });
    }

    // Build OAuth URL based on service
    let authUrl;
    const state = Buffer.from(JSON.stringify({ userId, serviceId })).toString('base64');
    const callbackUrl = redirectUri || `${process.env.FRONTEND_URL || 'http://localhost:3000'}/onboarding?service=${serviceId}&step=6`;

    if (serviceId === 'gmail' || serviceId === 'google-calendar') {
      // Google OAuth
      const googleClientId = process.env.GOOGLE_CLIENT_ID;
      const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;
      
      if (!googleClientId || !googleClientSecret) {
        return res.status(500).json({ 
          error: 'Configuration error',
          message: 'Google OAuth credentials not configured' 
        });
      }

      const scopes = serviceId === 'gmail' 
        ? 'https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.send'
        : 'https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/calendar.events';

      authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
        `client_id=${googleClientId}&` +
        `redirect_uri=${encodeURIComponent(callbackUrl)}&` +
        `response_type=code&` +
        `scope=${encodeURIComponent(scopes)}&` +
        `access_type=offline&` +
        `prompt=consent&` +
        `state=${state}`;
    } else if (serviceId === 'zoom') {
      // Zoom OAuth
      const zoomClientId = process.env.ZOOM_CLIENT_ID;
      
      if (!zoomClientId) {
        return res.status(500).json({ 
          error: 'Configuration error',
          message: 'Zoom OAuth credentials not configured' 
        });
      }

      authUrl = `https://zoom.us/oauth/authorize?` +
        `response_type=code&` +
        `client_id=${zoomClientId}&` +
        `redirect_uri=${encodeURIComponent(callbackUrl)}&` +
        `state=${state}`;
    }

    // Store pending connection in Firestore
    await db.collection('users').doc(userId).collection('service_connections').doc(serviceId).set({
      serviceId,
      status: 'pending',
      initiatedAt: admin.firestore.FieldValue.serverTimestamp(),
      state
    }, { merge: true });

    res.json({ 
      success: true,
      authUrl,
      serviceId 
    });
  } catch (error) {
    console.error('Error initiating OAuth:', error);
    res.status(500).json({ 
      error: 'Failed to initiate OAuth flow', 
      message: error.message 
    });
  }
});

/**
 * GET /api/services/callback/:serviceId
 * Handle OAuth callback and store tokens
 * Note: This route doesn't require authentication as it's called by OAuth provider
 */
app.get('/api/services/callback/:serviceId', async (req, res) => {
  try {
    const { serviceId } = req.params;
    const { code, state, error } = req.query;

    if (error) {
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/onboarding?error=${encodeURIComponent(error)}&step=6`);
    }

    if (!code) {
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/onboarding?error=no_code&step=6`);
    }

    // Verify state
    let decodedState;
    try {
      decodedState = JSON.parse(Buffer.from(state, 'base64').toString());
      if (decodedState.serviceId !== serviceId) {
        throw new Error('Invalid state');
      }
    } catch (err) {
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/onboarding?error=invalid_state&step=6`);
    }

    const userId = decodedState.userId;

    let tokens;
    const redirectUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/onboarding?service=${serviceId}&connected=true&step=6`;

    if (serviceId === 'gmail' || serviceId === 'google-calendar') {
      // Exchange code for tokens with Google
      const googleClientId = process.env.GOOGLE_CLIENT_ID;
      const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;
      const callbackUrl = `${process.env.BACKEND_URL || 'http://localhost:3001'}/api/services/callback/${serviceId}`;

      const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          code: code,
          client_id: googleClientId,
          client_secret: googleClientSecret,
          redirect_uri: callbackUrl,
          grant_type: 'authorization_code',
        }),
      });

      if (!tokenResponse.ok) {
        const errorData = await tokenResponse.json();
        throw new Error(`Google token exchange failed: ${errorData.error_description || errorData.error}`);
      }

      tokens = await tokenResponse.json();
    } else if (serviceId === 'zoom') {
      // Exchange code for tokens with Zoom
      const zoomClientId = process.env.ZOOM_CLIENT_ID;
      const zoomClientSecret = process.env.ZOOM_CLIENT_SECRET;
      const callbackUrl = `${process.env.BACKEND_URL || 'http://localhost:3001'}/api/services/callback/${serviceId}`;

      const tokenResponse = await fetch('https://zoom.us/oauth/token', {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${Buffer.from(`${zoomClientId}:${zoomClientSecret}`).toString('base64')}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: callbackUrl,
        }),
      });

      if (!tokenResponse.ok) {
        const errorData = await tokenResponse.json();
        throw new Error(`Zoom token exchange failed: ${errorData.reason || errorData.error}`);
      }

      tokens = await tokenResponse.json();
    }

    // Store tokens in Firestore (encrypted in production)
    const connectionData = {
      serviceId,
      status: 'connected',
      connectedAt: admin.firestore.FieldValue.serverTimestamp(),
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token || null,
      expiresAt: tokens.expires_in 
        ? admin.firestore.Timestamp.fromDate(new Date(Date.now() + tokens.expires_in * 1000))
        : null,
      tokenType: tokens.token_type || 'Bearer',
      scope: tokens.scope || null,
    };

    await db.collection('users').doc(userId).collection('service_connections').doc(serviceId).set(connectionData);

    // Update user's connectedServices array
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();
    const userData = userDoc.data();
    const connectedServices = userData?.connectedServices || [];
    
    if (!connectedServices.includes(serviceId)) {
      await userRef.update({
        connectedServices: [...connectedServices, serviceId],
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }

    res.redirect(redirectUrl);
  } catch (error) {
    console.error('Error handling OAuth callback:', error);
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/onboarding?error=${encodeURIComponent(error.message)}&step=6`);
  }
});

/**
 * GET /api/services/status
 * Get connection status for all services
 */
app.get('/api/services/status', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;

    const connectionsSnapshot = await db.collection('users').doc(userId)
      .collection('service_connections').get();

    const connections = {};
    connectionsSnapshot.docs.forEach(doc => {
      const data = doc.data();
      connections[data.serviceId] = {
        status: data.status,
        connectedAt: data.connectedAt?.toDate?.()?.toISOString() || null,
        expiresAt: data.expiresAt?.toDate?.()?.toISOString() || null,
      };
    });

    res.json({ connections });
  } catch (error) {
    console.error('Error fetching service status:', error);
    res.status(500).json({ 
      error: 'Failed to fetch service status', 
      message: error.message 
    });
  }
});

/**
 * DELETE /api/services/disconnect/:serviceId
 * Disconnect a service and revoke tokens
 */
app.delete('/api/services/disconnect/:serviceId', verifyToken, async (req, res) => {
  try {
    const { serviceId } = req.params;
    const userId = req.user.uid;

    // Get connection data
    const connectionRef = db.collection('users').doc(userId)
      .collection('service_connections').doc(serviceId);
    const connectionDoc = await connectionRef.get();

    if (!connectionDoc.exists) {
      return res.status(404).json({ 
        error: 'Connection not found',
        message: 'Service is not connected' 
      });
    }

    const connectionData = connectionDoc.data();

    // Revoke tokens based on service
    if (serviceId === 'gmail' || serviceId === 'google-calendar') {
      // Revoke Google token
      try {
        await fetch('https://oauth2.googleapis.com/revoke', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            token: connectionData.accessToken,
          }),
        });
      } catch (error) {
        console.error('Error revoking Google token:', error);
        // Continue with deletion even if revocation fails
      }
    } else if (serviceId === 'zoom') {
      // Revoke Zoom token
      try {
        const zoomClientId = process.env.ZOOM_CLIENT_ID;
        const zoomClientSecret = process.env.ZOOM_CLIENT_SECRET;
        
        await fetch('https://zoom.us/oauth/revoke', {
          method: 'POST',
          headers: {
            'Authorization': `Basic ${Buffer.from(`${zoomClientId}:${zoomClientSecret}`).toString('base64')}`,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            token: connectionData.accessToken,
          }),
        });
      } catch (error) {
        console.error('Error revoking Zoom token:', error);
        // Continue with deletion even if revocation fails
      }
    }

    // Delete connection document
    await connectionRef.delete();

    // Update user's connectedServices array
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();
    const userData = userDoc.data();
    const connectedServices = userData?.connectedServices || [];
    
    if (connectedServices.includes(serviceId)) {
      await userRef.update({
        connectedServices: connectedServices.filter(s => s !== serviceId),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }

    res.json({ 
      success: true,
      message: 'Service disconnected successfully' 
    });
  } catch (error) {
    console.error('Error disconnecting service:', error);
    res.status(500).json({ 
      error: 'Failed to disconnect service', 
      message: error.message 
    });
  }
});

// ============================================
// ADMIN ROUTES
// ============================================

/**
 * Helper function to verify admin role
 */
async function verifyAdmin(req, res, next) {
  try {
    const userId = req.user.uid;
    const userDoc = await db.collection('users').doc(userId).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ 
        error: 'User not found',
        message: 'User document does not exist' 
      });
    }
    
    const userData = userDoc.data();
    if (userData.role !== 'admin') {
      return res.status(403).json({ 
        error: 'Forbidden',
        message: 'Admin access required' 
      });
    }
    
    next();
  } catch (error) {
    console.error('Error verifying admin:', error);
    return res.status(500).json({ 
      error: 'Internal server error',
      message: 'Failed to verify admin status' 
    });
  }
}

/**
 * DELETE /api/admin/users/:userId
 * Delete a user completely (Firestore + Firebase Auth)
 * Requires admin authentication
 */
app.delete('/api/admin/users/:userId', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const adminUserId = req.user.uid;

    // Prevent self-deletion
    if (userId === adminUserId) {
      return res.status(400).json({ 
        error: 'Bad Request',
        message: 'You cannot delete your own account' 
      });
    }

    // Check if user exists in Firestore
    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists) {
      return res.status(404).json({ 
        error: 'User not found',
        message: 'User document does not exist in Firestore' 
      });
    }

    const userData = userDoc.data();
    const userEmail = userData.email;

    // Delete all user subcollections and related data
    const batch = db.batch();
    
    // Delete user's conversations and messages
    try {
      const conversationsSnapshot = await db.collection('users').doc(userId)
        .collection('conversations').get();
      
      for (const conversationDoc of conversationsSnapshot.docs) {
        // Delete all messages in this conversation
        const messagesSnapshot = await conversationDoc.ref.collection('messages').get();
        messagesSnapshot.docs.forEach(msgDoc => batch.delete(msgDoc.ref));
        batch.delete(conversationDoc.ref);
      }
    } catch (error) {
      console.error('Error deleting conversations:', error);
      // Continue with deletion even if subcollections fail
    }

    // Delete user's payment methods
    try {
      const paymentMethodsSnapshot = await db.collection('users').doc(userId)
        .collection('payment_methods').get();
      paymentMethodsSnapshot.docs.forEach(doc => batch.delete(doc.ref));
    } catch (error) {
      console.error('Error deleting payment methods:', error);
    }

    // Delete user's invoices
    try {
      const invoicesSnapshot = await db.collection('users').doc(userId)
        .collection('invoices').get();
      invoicesSnapshot.docs.forEach(doc => batch.delete(doc.ref));
    } catch (error) {
      console.error('Error deleting invoices:', error);
    }

    // Delete user's events
    try {
      const eventsSnapshot = await db.collection('events')
        .where('userId', '==', userId).get();
      eventsSnapshot.docs.forEach(doc => batch.delete(doc.ref));
    } catch (error) {
      console.error('Error deleting events:', error);
    }

    // Delete user's reminders
    try {
      const remindersSnapshot = await db.collection('reminders')
        .where('userId', '==', userId).get();
      remindersSnapshot.docs.forEach(doc => batch.delete(doc.ref));
    } catch (error) {
      console.error('Error deleting reminders:', error);
    }

    // Delete user's tasks
    try {
      const tasksSnapshot = await db.collection('tasks')
        .where('userId', '==', userId).get();
      tasksSnapshot.docs.forEach(doc => batch.delete(doc.ref));
    } catch (error) {
      console.error('Error deleting tasks:', error);
    }

    // Delete user's notifications
    try {
      const notificationsSnapshot = await db.collection('notifications')
        .where('userId', '==', userId).get();
      notificationsSnapshot.docs.forEach(doc => batch.delete(doc.ref));
    } catch (error) {
      console.error('Error deleting notifications:', error);
    }

    // Delete user's emails
    try {
      const emailsSnapshot = await db.collection('emails')
        .where('userId', '==', userId).get();
      emailsSnapshot.docs.forEach(doc => batch.delete(doc.ref));
    } catch (error) {
      console.error('Error deleting emails:', error);
    }

    // Delete user's extracted items
    try {
      const extractedItemsSnapshot = await db.collection('extracted_items')
        .where('userId', '==', userId).get();
      extractedItemsSnapshot.docs.forEach(doc => batch.delete(doc.ref));
    } catch (error) {
      console.error('Error deleting extracted items:', error);
    }

    // Delete user document from Firestore
    batch.delete(db.collection('users').doc(userId));

    // Commit all Firestore deletions
    await batch.commit();

    // Delete user from Firebase Auth
    try {
      await admin.auth().deleteUser(userId);
      console.log(`✅ Successfully deleted Firebase Auth user: ${userId} (${userEmail})`);
    } catch (authError) {
      // If user doesn't exist in Auth (already deleted), that's okay
      if (authError.code === 'auth/user-not-found') {
        console.log(`⚠️  User ${userId} not found in Firebase Auth (may have been already deleted)`);
      } else {
        throw authError;
      }
    }

    res.json({ 
      success: true, 
      message: 'User deleted successfully',
      deletedUserId: userId,
      deletedEmail: userEmail
    });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ 
      error: 'Failed to delete user', 
      message: error.message 
    });
  }
});

/**
 * PATCH /api/admin/users/:userId/disable
 * Disable or enable a user account
 * Requires admin authentication
 */
app.patch('/api/admin/users/:userId/disable', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { disabled = true } = req.body;

    // Check if user exists
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ 
        error: 'User not found',
        message: 'User document does not exist' 
      });
    }

    // Update disabled status
    await userRef.update({
      disabled: disabled,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // Also disable/enable in Firebase Auth
    try {
      await admin.auth().updateUser(userId, {
        disabled: disabled
      });
    } catch (authError) {
      // If user doesn't exist in Auth, that's okay
      if (authError.code !== 'auth/user-not-found') {
        throw authError;
      }
    }

    res.json({ 
      success: true, 
      message: `User account ${disabled ? 'disabled' : 'enabled'} successfully`,
      userId,
      disabled
    });
  } catch (error) {
    console.error('Error updating user status:', error);
    res.status(500).json({ 
      error: 'Failed to update user status', 
      message: error.message 
    });
  }
});

// ============================================
// ADMIN API USAGE ROUTES
// ============================================

/**
 * GET /api/admin/api-usage/stats
 * Get overall API usage statistics with percentage changes
 */
app.get('/api/admin/api-usage/stats', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { period = 'daily' } = req.query;
    
    const now = new Date();
    let startDate, previousStartDate, previousEndDate;
    
    // Calculate current period dates
    if (period === 'daily') {
      startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      // Previous day
      previousStartDate = new Date(startDate);
      previousStartDate.setDate(previousStartDate.getDate() - 1);
      previousEndDate = new Date(startDate);
    } else if (period === 'weekly') {
      const dayOfWeek = now.getDay();
      startDate = new Date(now.getTime() - (dayOfWeek * 24 * 60 * 60 * 1000));
      startDate.setHours(0, 0, 0, 0);
      // Previous week
      previousStartDate = new Date(startDate);
      previousStartDate.setDate(previousStartDate.getDate() - 7);
      previousEndDate = new Date(startDate);
    } else {
      startDate = new Date(now.getFullYear(), now.getMonth(), 1);
      // Previous month
      previousStartDate = new Date(now.getFullYear(), now.getMonth() - 1, 1);
      previousEndDate = new Date(now.getFullYear(), now.getMonth(), 1);
    }
    
    // Get all usage records in current period from in-memory storage
    const startTimestamp = startDate.getTime();
    const endTimestamp = period === 'daily' 
      ? new Date(startDate.getTime() + 24 * 60 * 60 * 1000).getTime()
      : period === 'weekly'
      ? new Date(startDate.getTime() + 7 * 24 * 60 * 60 * 1000).getTime()
      : new Date(startDate.getFullYear(), startDate.getMonth() + 1, 1).getTime();
    
    const previousEndTimestamp = previousEndDate.getTime();
    
    // Filter recent activity for current period
    const currentPeriodActivity = apiUsageStore.recentActivity.filter(activity => {
      const activityTime = new Date(activity.timestamp).getTime();
      return activityTime >= startTimestamp && activityTime < endTimestamp;
    });
    
    // Filter recent activity for previous period
    const previousPeriodActivity = apiUsageStore.recentActivity.filter(activity => {
      const activityTime = new Date(activity.timestamp).getTime();
      return activityTime >= previousStartDate.getTime() && activityTime < previousEndTimestamp;
    });
    
    // Calculate current period stats
    let totalRequests = 0;
    let totalCost = 0;
    let deepseekRequests = 0;
    let elevenlabsRequests = 0;
    let deepseekCost = 0;
    let elevenlabsCost = 0;
    let rateLimitHits = 0;
    let blockedRequests = 0;
    let totalResponseTime = 0;
    let responseTimeCount = 0;
    const activeUsers = new Set();
    
    currentPeriodActivity.forEach(activity => {
      totalRequests++;
      const cost = activity.cost || 0;
      totalCost += cost;
      activeUsers.add(activity.userId);
      
      if (activity.apiType === 'deepseek') {
        deepseekRequests++;
        deepseekCost += cost;
      } else if (activity.apiType === 'elevenlabs') {
        elevenlabsRequests++;
        elevenlabsCost += cost;
      }
      
      if (activity.rateLimitExceeded) {
        rateLimitHits++;
      }
      if (activity.blocked) {
        blockedRequests++;
      }
      
      if (activity.responseTime) {
        totalResponseTime += activity.responseTime;
        responseTimeCount++;
      }
    });
    
    // Calculate previous period stats for comparison
    let prevTotalRequests = 0;
    let prevTotalCost = 0;
    let prevRateLimitHits = 0;
    const prevActiveUsers = new Set();
    
    previousPeriodActivity.forEach(activity => {
      prevTotalRequests++;
      prevTotalCost += activity.cost || 0;
      prevActiveUsers.add(activity.userId);
      
      if (activity.rateLimitExceeded) {
        prevRateLimitHits++;
      }
    });
    
    // Calculate percentage changes
    const calculatePercentageChange = (current, previous) => {
      if (previous === 0) return current > 0 ? 100 : 0;
      return ((current - previous) / previous) * 100;
    };
    
    const totalRequestsChange = calculatePercentageChange(totalRequests, prevTotalRequests);
    const totalCostChange = calculatePercentageChange(totalCost, prevTotalCost);
    const rateLimitHitsChange = calculatePercentageChange(rateLimitHits, prevRateLimitHits);
    const activeUsersChange = calculatePercentageChange(activeUsers.size, prevActiveUsers.size);
    
    // Calculate usage percentages (based on total requests vs a reasonable baseline)
    // For progress bars, we'll use a percentage based on the total requests across all APIs
    const totalApiRequests = deepseekRequests + elevenlabsRequests;
    const deepseekUsagePercent = totalApiRequests > 0 ? (deepseekRequests / totalApiRequests) * 100 : 0;
    const elevenlabsUsagePercent = totalApiRequests > 0 ? (elevenlabsRequests / totalApiRequests) * 100 : 0;
    
    res.json({
      totalRequests,
      totalCost: parseFloat(totalCost.toFixed(2)),
      activeUsers: activeUsers.size,
      rateLimitHits,
      blockedRequests,
      deepseekRequests,
      elevenlabsRequests,
      deepseekCost: parseFloat(deepseekCost.toFixed(2)),
      elevenlabsCost: parseFloat(elevenlabsCost.toFixed(2)),
      avgResponseTime: responseTimeCount > 0 ? Math.round(totalResponseTime / responseTimeCount) : 0,
      // Percentage changes
      totalRequestsChange: parseFloat(totalRequestsChange.toFixed(1)),
      totalCostChange: parseFloat(totalCostChange.toFixed(1)),
      rateLimitHitsChange: parseFloat(rateLimitHitsChange.toFixed(1)),
      activeUsersChange: parseFloat(activeUsersChange.toFixed(1)),
      // Usage percentages for progress bars
      deepseekUsagePercent: parseFloat(deepseekUsagePercent.toFixed(1)),
      elevenlabsUsagePercent: parseFloat(elevenlabsUsagePercent.toFixed(1)),
      period
    });
  } catch (error) {
    console.error('Error fetching usage stats:', error);
    res.status(500).json({ 
      error: 'Failed to fetch usage stats', 
      message: error.message 
    });
  }
});

/**
 * GET /api/admin/api-usage/users
 * Get user-level API usage data
 */
app.get('/api/admin/api-usage/users', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { period = 'daily', plan = 'all', sort = 'requests', order = 'desc' } = req.query;
    
    const now = new Date();
    let startDate;
    
    if (period === 'daily') {
      startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    } else if (period === 'weekly') {
      const dayOfWeek = now.getDay();
      startDate = new Date(now.getTime() - (dayOfWeek * 24 * 60 * 60 * 1000));
      startDate.setHours(0, 0, 0, 0);
    } else {
      startDate = new Date(now.getFullYear(), now.getMonth(), 1);
    }
    
    const startTimestamp = startDate.getTime();
    const endTimestamp = period === 'daily' 
      ? new Date(startDate.getTime() + 24 * 60 * 60 * 1000).getTime()
      : period === 'weekly'
      ? new Date(startDate.getTime() + 7 * 24 * 60 * 60 * 1000).getTime()
      : new Date(startDate.getFullYear(), startDate.getMonth() + 1, 1).getTime();
    
    // Get usage from in-memory storage
    const periodActivity = apiUsageStore.recentActivity.filter(activity => {
      const activityTime = new Date(activity.timestamp).getTime();
      return activityTime >= startTimestamp && activityTime < endTimestamp;
    });
    
    const userUsageMap = {};
    
    periodActivity.forEach(activity => {
      const userId = activity.userId;
      
      if (!userUsageMap[userId]) {
        userUsageMap[userId] = {
          userId,
          deepseekRequests: 0,
          elevenlabsRequests: 0,
          totalRequests: 0,
          deepseekCost: 0,
          elevenlabsCost: 0,
          totalCost: 0,
          rateLimitHits: 0,
          blockedRequests: 0,
          planId: activity.planId || 'student',
          lastRequestAt: null
        };
      }
      
      const usage = userUsageMap[userId];
      usage.totalRequests++;
      usage.totalCost += activity.cost || 0;
      
      if (activity.apiType === 'deepseek') {
        usage.deepseekRequests++;
        usage.deepseekCost += activity.cost || 0;
      } else if (activity.apiType === 'elevenlabs') {
        usage.elevenlabsRequests++;
        usage.elevenlabsCost += activity.cost || 0;
      }
      
      if (activity.rateLimitExceeded) {
        usage.rateLimitHits++;
      }
      if (activity.blocked) {
        usage.blockedRequests++;
      }
      
      const timestamp = new Date(activity.timestamp);
      if (!usage.lastRequestAt || timestamp > usage.lastRequestAt) {
        usage.lastRequestAt = timestamp;
      }
    });
    
    // Fetch user details
    const users = [];
    for (const userId in userUsageMap) {
      try {
        const userDoc = await db.collection('users').doc(userId).get();
        if (userDoc.exists) {
          const userData = userDoc.data();
          const usage = userUsageMap[userId];
          
          // Get plan name
          let planName = 'Student';
          if (usage.planId === 'professional') planName = 'Professional';
          else if (usage.planId === 'executive') planName = 'Executive';
          else if (usage.planId === 'team') planName = 'Team';
          
          // Filter by plan if specified
          if (plan !== 'all' && usage.planId !== plan) {
            continue;
          }
          
          users.push({
            ...usage,
            userName: userData.fullName || userData.displayName || userData.onboardingData?.userName || 'Unknown',
            userEmail: userData.email || 'No email',
            planName,
            lastRequestAt: usage.lastRequestAt
          });
        }
      } catch (error) {
        console.error(`Error fetching user ${userId}:`, error);
      }
    }
    
    // Sort users
    users.sort((a, b) => {
      let aVal, bVal;
      if (sort === 'requests') {
        aVal = a.totalRequests;
        bVal = b.totalRequests;
      } else if (sort === 'cost') {
        aVal = a.totalCost;
        bVal = b.totalCost;
      } else {
        aVal = a.userName.toLowerCase();
        bVal = b.userName.toLowerCase();
      }
      
      if (order === 'asc') {
        return aVal > bVal ? 1 : -1;
      } else {
        return aVal < bVal ? 1 : -1;
      }
    });
    
    res.json({ users });
  } catch (error) {
    console.error('Error fetching user usage:', error);
    res.status(500).json({ 
      error: 'Failed to fetch user usage', 
      message: error.message 
    });
  }
});

/**
 * GET /api/admin/api-usage/activity
 * Get recent API activity (from in-memory storage, no Firestore)
 */
app.get('/api/admin/api-usage/activity', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const limitCount = parseInt(req.query.limit) || 50;
    
    // Get recent activity from in-memory storage (already sorted by timestamp, newest last)
    const recentActivity = [...apiUsageStore.recentActivity]
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, limitCount)
      .map(activity => ({
        id: activity.id,
        userId: activity.userId,
        apiType: activity.apiType,
        timestamp: activity.timestamp,
        cost: activity.cost || 0,
        success: activity.success || false,
        blocked: activity.blocked || false,
        rateLimitExceeded: activity.rateLimitExceeded || false,
        userPlan: activity.planId || 'student',
        requestSize: activity.requestSize || null,
        responseTime: activity.responseTime || null
      }));
    
    res.json({ activity: recentActivity });
  } catch (error) {
    console.error('Error fetching activity:', error);
    res.status(500).json({ 
      error: 'Failed to fetch activity', 
      message: error.message 
    });
  }
});

/**
 * PATCH /api/admin/api-usage/users/:userId/block
 * Block or unblock a user from API access
 */
app.patch('/api/admin/api-usage/users/:userId/block', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { blocked } = req.body;
    
    // Update user document
    await db.collection('users').doc(userId).update({
      apiBlocked: blocked,
      apiBlockedAt: blocked ? admin.firestore.FieldValue.serverTimestamp() : null,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    res.json({ 
      success: true, 
      message: `User ${blocked ? 'blocked' : 'unblocked'} from API access`,
      userId,
      blocked
    });
  } catch (error) {
    console.error('Error blocking user:', error);
    res.status(500).json({ 
      error: 'Failed to block user', 
      message: error.message 
    });
  }
});

// ============================================
// API USAGE HELPER ROUTES (Called by Next.js API routes)
// ============================================

/**
 * POST /api/auth/verify
 * Verify Firebase token and return user ID
 */
app.post('/api/auth/verify', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split('Bearer ')[1];
    const decodedToken = await admin.auth().verifyIdToken(token);
    
    res.json({ 
      uid: decodedToken.uid,
      email: decodedToken.email 
    });
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(401).json({ 
      error: 'Invalid or expired token',
      message: error.message 
    });
  }
});

/**
 * GET /api/api-usage/check-block
 * Check if user is blocked from API access
 */
app.get('/api/api-usage/check-block', verifyToken, async (req, res) => {
  try {
    const { userId } = req.query;
    const requestingUserId = req.user.uid;
    
    // Users can only check their own block status
    if (userId !== requestingUserId) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists) {
      return res.json({ blocked: false });
    }
    
    const userData = userDoc.data();
    res.json({ blocked: userData.apiBlocked || false });
  } catch (error) {
    console.error('Error checking block status:', error);
    res.status(500).json({ 
      error: 'Failed to check block status', 
      message: error.message 
    });
  }
});

/**
 * GET /api/api-usage/check-rate-limit
 * Check if user has exceeded rate limits
 */
app.get('/api/api-usage/check-rate-limit', verifyToken, async (req, res) => {
  try {
    const { userId, apiType } = req.query;
    const requestingUserId = req.user.uid;
    
    // Users can only check their own rate limits
    if (userId !== requestingUserId) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const rateLimitCheck = await checkRateLimit(userId, apiType);
    
    if (!rateLimitCheck.allowed) {
      const message = rateLimitCheck.dailyExceeded 
        ? `Daily limit of ${rateLimitCheck.dailyLimit} requests exceeded. You have used ${rateLimitCheck.dailyCount} requests today.`
        : `Monthly limit of ${rateLimitCheck.monthlyLimit} requests exceeded. You have used ${rateLimitCheck.monthlyCount} requests this month.`;
      
      const resetTime = rateLimitCheck.dailyExceeded 
        ? new Date(new Date().setHours(24, 0, 0, 0)).toISOString()
        : new Date(new Date().getFullYear(), new Date().getMonth() + 1, 1).toISOString();
      
      return res.json({
        allowed: false,
        message,
        limit: rateLimitCheck.dailyExceeded ? rateLimitCheck.dailyLimit : rateLimitCheck.monthlyLimit,
        used: rateLimitCheck.dailyExceeded ? rateLimitCheck.dailyCount : rateLimitCheck.monthlyCount,
        resetTime,
        planId: rateLimitCheck.planId
      });
    }
    
    res.json({
      allowed: true,
      dailyCount: rateLimitCheck.dailyCount,
      monthlyCount: rateLimitCheck.monthlyCount,
      dailyLimit: rateLimitCheck.dailyLimit,
      monthlyLimit: rateLimitCheck.monthlyLimit,
      planId: rateLimitCheck.planId
    });
  } catch (error) {
    console.error('Error checking rate limit:', error);
    // Fail open - allow request if check fails
    res.json({ 
      allowed: true,
      error: error.message 
    });
  }
});

/**
 * POST /api/api-usage/record
 * Record API usage (called by Next.js API routes)
 */
app.post('/api/api-usage/record', verifyToken, async (req, res) => {
  try {
    const { userId, apiType, success, blocked, rateLimitExceeded, responseTime, requestSize } = req.body;
    const requestingUserId = req.user.uid;
    
    // Users can only record their own usage
    if (userId !== requestingUserId) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    await recordAPIUsage(userId, apiType, success, blocked, rateLimitExceeded, responseTime, requestSize);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error recording usage:', error);
    // Don't fail the request if recording fails
    res.json({ success: false, error: error.message });
  }
});

// ============================================
// HEALTH CHECK
// ============================================

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    service: 'MAI-PA API'
  });
});

// ============================================
// ERROR HANDLING
// ============================================

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(`🚀 MAI-PA API Server running on port ${PORT}`);
  console.log(`📡 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔐 Environment: ${process.env.NODE_ENV || 'development'}`);
});

// ============================================
// NOTES FOR IMPLEMENTATION
// ============================================

/**
 * FIRESTORE SETUP:
 * 
 * ✅ Notifications are now using Firestore!
 * 
 * 1. Firestore Indexes Required:
 *    You may need to create composite indexes in Firebase Console for these queries:
 *    - Collection: notifications
 *      - Fields: userId (Ascending), is_archived (Ascending), created_at (Descending)
 *    - Collection: notifications
 *      - Fields: userId (Ascending), is_read (Ascending), is_archived (Ascending)
 *    - Collection: notifications
 *      - Fields: userId (Ascending), is_archived (Ascending), created_at (Descending)
 * 
 *    If you get an index error, Firebase will provide a direct link to create it.
 * 
 * 2. Firestore Security Rules:
 *    Make sure your Firestore security rules allow the service account to read/write:
 *    (The service account bypasses security rules, but you should still set proper rules for client access)
 * 
 * 3. Other Collections (Calendar, Tasks, etc.):
 *    Currently using in-memory arrays. To migrate to Firestore:
 *    - Follow the same pattern as notifications
 *    - Use db.collection('collectionName') instead of arrays
 *    - Use Firestore queries (where, orderBy, limit) instead of array filters
 *    - Use batch operations for bulk updates
 * 
 * 4. Data Validation:
 *    Consider adding validation using libraries like Joi or Yup before saving to Firestore
 * 
 * 5. Pagination:
 *    For large datasets, implement pagination using Firestore's startAfter() and limit()
 * 
 * EMAIL PROCESSING:
 * 
 * 1. Integrate with email providers (Gmail, Outlook, etc.) using their APIs
 * 
 * 2. Use AI/ML service to extract events, reminders, and tasks from emails:
 *    - OpenAI GPT-4
 *    - Google Cloud AI
 *    - Custom NLP models
 * 
 * 3. Set up webhooks or polling to process new emails
 * 
 * NOTIFICATIONS:
 * 
 * 1. Implement real-time notifications using WebSockets or Server-Sent Events
 * 
 * 2. Add push notification support for mobile apps
 * 
 * 3. Create notification templates for different types
 * 
 * SECURITY:
 * 
 * 1. Add rate limiting (use express-rate-limit)
 * 
 * 2. Implement request validation
 * 
 * 3. Add CORS configuration for production
 * 
 * 4. Use HTTPS in production
 * 
 * 5. Add logging and monitoring (Winston, Morgan)
 * 
 * TESTING:
 * 
 * 1. Add unit tests (Jest)
 * 
 * 2. Add integration tests
 * 
 * 3. Add API documentation (Swagger/OpenAPI)
 */