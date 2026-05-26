import { Router } from "express";
import { JSONFilePreset } from "lowdb/node";
import bcrypt from "bcryptjs";
import { randomUUID } from "crypto";
import type { Request, Response } from "express";
import type { Session } from "express-session";

declare module "express-session" {
  interface SessionData {
    userId?: string;
    isAdmin?: boolean;
  }
}

interface User {
  id: string;
  firstName: string;
  username: string;
  passwordHash: string;
  avatarEmoji: string;
  school: string;
  totalScore: number;
  scamBestScore: number;
  quizBestScore: number;
  passwordBestScore: number;
  lastSpotScamDate: string;
  lastQuizDate: string;
  lastPasswordDate: string;
  badgesEarned: string[];
  missionCounts: Record<string, number>;
  strongPasswordCount: number;
  speedAnswers: number;
  lastActive: string;
  createdAt: string;
}

interface DbData {
  users: User[];
}

const ALL_BADGES = [
  { id: "scam_spotter", name: "Scam Spotter", emoji: "🕵️", description: "Finish 3 Spot the Scam rounds" },
  { id: "password_hero", name: "Password Hero", emoji: "🔐", description: "Make 3 strong passwords" },
  { id: "cyber_champion", name: "Cyber Champion", emoji: "🛡️", description: "Reach 200 total points" },
  { id: "safety_surfer", name: "Safety Surfer", emoji: "🏄", description: "Try all 3 mission types" },
  { id: "speed_star", name: "Speed Star", emoji: "⚡", description: "Answer 10 questions in time" },
];

const ADMIN_PASSWORD = "admin123";

let dbPromise: Promise<Awaited<ReturnType<typeof JSONFilePreset<DbData>>>>;

function todayStr(): string {
  return new Date().toISOString().slice(0, 10);
}

async function getDb() {
  if (!dbPromise) {
    dbPromise = JSONFilePreset<DbData>("db.json", { users: [] });
  }
  return await dbPromise;
}

function safeUser(user: User) {
  return {
    id: user.id,
    firstName: user.firstName,
    username: user.username,
    avatarEmoji: user.avatarEmoji,
    school: user.school,
    totalScore: user.totalScore,
    badgesEarned: user.badgesEarned,
  };
}

function computeBadges(user: User): string[] {
  const earned: string[] = [...user.badgesEarned];
  const add = (id: string) => { if (!earned.includes(id)) earned.push(id); };
  const scamCount = user.missionCounts?.scam ?? 0;
  const quizCount = user.missionCounts?.quiz ?? 0;
  const pwCount = user.missionCounts?.password ?? 0;
  if (scamCount >= 3) add("scam_spotter");
  if ((user.strongPasswordCount ?? 0) >= 3) add("password_hero");
  if (user.totalScore >= 200) add("cyber_champion");
  if (scamCount >= 1 && quizCount >= 1 && pwCount >= 1) add("safety_surfer");
  if ((user.speedAnswers ?? 0) >= 10) add("speed_star");
  return earned;
}

function checkAdminPass(req: Request): boolean {
  const pass = req.query["pass"] || req.body?.pass;
  return pass === ADMIN_PASSWORD;
}

const router = Router();

// POST /api/register
router.post("/register", async (req: Request, res: Response) => {
  try {
    const { firstName, username, password, avatarEmoji, school } = req.body;
    if (!firstName || !username || !password || !avatarEmoji || !school) {
      res.status(400).json({ error: "All fields are required! 🤔" });
      return;
    }
    if (password.length < 3) {
      res.status(400).json({ error: "Password too short! Try again 😊" });
      return;
    }
    const db = await getDb();
    const existing = db.data.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (existing) {
      res.status(400).json({ error: "That username is taken! Try another one 😊" });
      return;
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const now = new Date().toISOString();
    const user: User = {
      id: randomUUID(),
      firstName: firstName.trim(),
      username: username.trim().toLowerCase(),
      passwordHash,
      avatarEmoji,
      school: school.trim(),
      totalScore: 0,
      scamBestScore: 0,
      quizBestScore: 0,
      passwordBestScore: 0,
      lastSpotScamDate: "",
      lastQuizDate: "",
      lastPasswordDate: "",
      badgesEarned: [],
      missionCounts: { scam: 0, quiz: 0, password: 0 },
      strongPasswordCount: 0,
      speedAnswers: 0,
      lastActive: now,
      createdAt: now,
    };
    db.data.users.push(user);
    await db.write();
    (req.session as Session & { userId?: string }).userId = user.id;
    res.status(201).json({ user: safeUser(user) });
  } catch (err) {
    req.log.error(err, "Register error");
    res.status(500).json({ error: "Something went wrong! 😅" });
  }
});

// POST /api/login
router.post("/login", async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      res.status(400).json({ error: "Please fill in all fields 😊" });
      return;
    }
    const db = await getDb();
    const user = db.data.users.find(u => u.username === username.toLowerCase());
    if (!user) {
      res.status(401).json({ error: "Hmm, we can't find that player 🤔" });
      return;
    }
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      res.status(401).json({ error: "Oops! Wrong secret word 😊 Try again!" });
      return;
    }
    (req.session as Session & { userId?: string }).userId = user.id;
    res.json({ user: safeUser(user) });
  } catch (err) {
    req.log.error(err, "Login error");
    res.status(500).json({ error: "Something went wrong! 😅" });
  }
});

// POST /api/logout
router.post("/logout", (req: Request, res: Response) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// GET /api/me
router.get("/me", async (req: Request, res: Response) => {
  const userId = (req.session as Session & { userId?: string }).userId;
  if (!userId) {
    res.status(401).json({ error: "Not logged in 🔒" });
    return;
  }
  try {
    const db = await getDb();
    const user = db.data.users.find(u => u.id === userId);
    if (!user) {
      res.status(401).json({ error: "User not found 🔒" });
      return;
    }
    res.json(safeUser(user));
  } catch (err) {
    req.log.error(err, "Get me error");
    res.status(500).json({ error: "Something went wrong! 😅" });
  }
});

// POST /api/score — FIX 2: daily limit + best score (Math.max, not accumulate)
router.post("/score", async (req: Request, res: Response) => {
  const userId = (req.session as Session & { userId?: string }).userId;
  if (!userId) {
    res.status(401).json({ error: "Not logged in 🔒" });
    return;
  }
  try {
    const { points, missionType, isStrong, speedBonus } = req.body;
    const db = await getDb();
    const userIdx = db.data.users.findIndex(u => u.id === userId);
    if (userIdx === -1) {
      res.status(401).json({ error: "User not found 🔒" });
      return;
    }
    const user = db.data.users[userIdx];
    const today = todayStr();
    let pointsAdded = false;
    const pts = Number(points) || 0;

    // Init fields for older accounts
    if (!user.missionCounts) user.missionCounts = { scam: 0, quiz: 0, password: 0 };
    if (!user.lastSpotScamDate) user.lastSpotScamDate = "";
    if (!user.lastQuizDate) user.lastQuizDate = "";
    if (!user.lastPasswordDate) user.lastPasswordDate = "";
    if (user.scamBestScore == null) user.scamBestScore = 0;
    if (user.quizBestScore == null) user.quizBestScore = 0;
    if (user.passwordBestScore == null) user.passwordBestScore = 0;

    // Always update mission counts (for badges), speed, strong count
    if (missionType === "scam") user.missionCounts.scam = (user.missionCounts.scam ?? 0) + 1;
    if (missionType === "quiz") user.missionCounts.quiz = (user.missionCounts.quiz ?? 0) + 1;
    if (missionType === "password") user.missionCounts.password = (user.missionCounts.password ?? 0) + 1;
    if (isStrong) user.strongPasswordCount = (user.strongPasswordCount ?? 0) + 1;
    if (speedBonus) user.speedAnswers = (user.speedAnswers ?? 0) + Number(speedBonus);
    user.lastActive = new Date().toISOString();

    // FIX 2: daily limit + keep BEST score (Math.max, not +=)
    if (missionType === "scam" && user.lastSpotScamDate !== today) {
      user.lastSpotScamDate = today;
      user.scamBestScore = Math.max(user.scamBestScore, pts);
      user.totalScore = user.scamBestScore + user.quizBestScore + user.passwordBestScore;
      pointsAdded = true;
    } else if (missionType === "quiz" && user.lastQuizDate !== today) {
      user.lastQuizDate = today;
      user.quizBestScore = Math.max(user.quizBestScore, pts);
      user.totalScore = user.scamBestScore + user.quizBestScore + user.passwordBestScore;
      pointsAdded = true;
    } else if (missionType === "password" && user.lastPasswordDate !== today) {
      user.lastPasswordDate = today;
      user.passwordBestScore = Math.max(user.passwordBestScore, pts);
      user.totalScore = user.scamBestScore + user.quizBestScore + user.passwordBestScore;
      pointsAdded = true;
    }

    const newEarned = computeBadges(user);
    const newBadges = newEarned.filter(b => !user.badgesEarned.includes(b));
    user.badgesEarned = newEarned;
    db.data.users[userIdx] = user;
    await db.write();
    res.json({ totalScore: user.totalScore, newBadges, pointsAdded });
  } catch (err) {
    req.log.error(err, "Score error");
    res.status(500).json({ error: "Something went wrong! 😅" });
  }
});

// GET /api/leaderboard
router.get("/leaderboard", async (req: Request, res: Response) => {
  try {
    const db = await getDb();
    const sorted = [...db.data.users]
      .sort((a, b) => b.totalScore - a.totalScore)
      .slice(0, 10)
      .map((u, i) => ({
        rank: i + 1,
        id: u.id,
        firstName: u.firstName,
        avatarEmoji: u.avatarEmoji,
        school: u.school,
        totalScore: u.totalScore,
      }));
    res.json(sorted);
  } catch (err) {
    req.log.error(err, "Leaderboard error");
    res.status(500).json({ error: "Something went wrong! 😅" });
  }
});

// GET /api/badges/:userId
router.get("/badges/:userId", async (req: Request, res: Response) => {
  try {
    const db = await getDb();
    const user = db.data.users.find(u => u.id === req.params.userId);
    if (!user) {
      res.status(404).json({ error: "Player not found 🤔" });
      return;
    }
    res.json({ earned: user.badgesEarned, all: ALL_BADGES });
  } catch (err) {
    req.log.error(err, "Badges error");
    res.status(500).json({ error: "Something went wrong! 😅" });
  }
});

// ─── ADMIN ROUTES ────────────────────────────────────────

// GET /api/admin/data?pass=admin123
router.get("/admin/data", async (req: Request, res: Response) => {
  if (!checkAdminPass(req)) {
    res.status(401).json({ error: "Wrong password" });
    return;
  }
  try {
    const db = await getDb();
    const rows = db.data.users.map(u => ({
      id: u.id,
      firstName: u.firstName,
      school: u.school,
      scamScore: u.scamBestScore ?? 0,
      quizScore: u.quizBestScore ?? 0,
      passwordScore: u.passwordBestScore ?? 0,
      totalScore: u.totalScore,
      badges: u.badgesEarned,
      lastActive: u.lastActive ? u.lastActive.slice(0, 10) : u.createdAt?.slice(0, 10) || "—",
    }));
    res.json(rows);
  } catch (err) {
    req.log.error(err, "Admin data error");
    res.status(500).json({ error: "Something went wrong" });
  }
});

// DELETE /api/admin/users/:id?pass=admin123
router.delete("/admin/users/:id", async (req: Request, res: Response) => {
  if (!checkAdminPass(req)) {
    res.status(401).json({ error: "Wrong password" });
    return;
  }
  try {
    const db = await getDb();
    const before = db.data.users.length;
    db.data.users = db.data.users.filter(u => u.id !== req.params.id);
    if (db.data.users.length === before) {
      res.status(404).json({ error: "User not found" });
      return;
    }
    await db.write();
    res.json({ success: true });
  } catch (err) {
    req.log.error(err, "Admin delete error");
    res.status(500).json({ error: "Something went wrong" });
  }
});

// GET /api/admin/csv?pass=admin123  — updated headers (Admin panel update)
router.get("/admin/csv", async (req: Request, res: Response) => {
  if (!checkAdminPass(req)) {
    res.status(401).json({ error: "Wrong password" });
    return;
  }
  try {
    const db = await getDb();
    const header = "Name,School,Spot Scam Score,Picture Score,Password Score,Total Score,Badges Earned,Last Active";
    const rows = db.data.users.map(u => {
      const badges = (u.badgesEarned || []).join("|");
      const lastActive = u.lastActive ? u.lastActive.slice(0, 10) : u.createdAt?.slice(0, 10) || "";
      return [
        `"${u.firstName}"`,
        `"${u.school}"`,
        u.scamBestScore ?? 0,
        u.quizBestScore ?? 0,
        u.passwordBestScore ?? 0,
        u.totalScore,
        `"${badges}"`,
        `"${lastActive}"`,
      ].join(",");
    });
    const csv = [header, ...rows].join("\n");
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", 'attachment; filename="cybershield-kids.csv"');
    res.send(csv);
  } catch (err) {
    req.log.error(err, "Admin CSV error");
    res.status(500).json({ error: "Something went wrong" });
  }
});

export default router;
