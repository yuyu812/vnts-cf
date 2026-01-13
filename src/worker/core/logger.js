let globalLogger = null;
let isInitialized = false;
let pendingStorage = null;

export class Logger {
  constructor(env) {
    this.env = env;

    // 调试输出：显示读取到的环境变量
    // console.log(`[Logger] 当前环境变量:`, JSON.stringify(env));
    // console.log(`[Logger] 日志等级:`, env.LOG_LEVEL || '未设置，使用默认值 warn');

    this.levels = {
      error: 0,
      warn: 1,
      info: 2,
      debug: 3,
    };

    // 获取配置的日志级别，支持大小写兼容
    const configLevel = (env.LOG_LEVEL || "warn").toLowerCase();
    this.currentLevel = this.levels[configLevel] ?? this.levels.warn;

    // 检查是否启用存储日志
    this.logPassword = env.LOG_PASSWORD || null;
    this.enableStorage = this.logPassword !== null && this.logPassword !== "";

    // 检查是否为本地部署
    this.isLocalDeploy = env.LOCAL_DEPLOY === "true";

    // 存储相关属性
    this.storageBuffer = [];
    this.maxStorageLogs = 1000; // 保留最近1000条日志
    this.storage = null; // 将在 RelayRoom 中设置

    // console.log(`[Logger] 当前日志等级: ${configLevel} (级别: ${this.currentLevel})`);
  }

  // 加载现有日志
  async loadExistingLogs() {
    if (!this.enableStorage || !this.storage) return;

    try {
      const existingLogs = (await this.storage.get("operationLogs")) || [];
      this.storageBuffer = existingLogs;

      // 如果超过最大数量，保留最新的日志
      if (this.storageBuffer.length > this.maxStorageLogs) {
        this.storageBuffer = this.storageBuffer.slice(-this.maxStorageLogs);
      }

      console.log(
        `[Logger-存储] 加载了 ${this.storageBuffer.length} 条现有日志`
      );
    } catch (error) {
      console.error(`[Logger-存储] 加载现有日志失败: ${error.message}`);
      this.storageBuffer = [];
    }
  }

  // 设置 storage 引用
  async setStorage(storage) {
    this.storage = storage;
    // 加载现有日志
    await this.loadExistingLogs();
  }

  // 写入存储
  async writeToStorage(level, message) {
    // 本地部署时不写入存储
    if (this.isLocalDeploy) {
      return;
    }
    if (!this.enableStorage || !this.storage) return;

    try {
      // 移除时间和等级前缀 [YYYY-MM-DD HH:MM:SS] [级别] :
      const cleanMessage = message.replace(
        /^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[.*?\] : /,
        ""
      );
      const logEntry = {
        timestamp: new Date().toISOString(),
        level: level,
        message: cleanMessage,
      };

      this.storageBuffer.push(logEntry);

      // 限制日志数量
      if (this.storageBuffer.length > this.maxStorageLogs) {
        this.storageBuffer = this.storageBuffer.slice(-this.maxStorageLogs);
      }

      // 写入 storage
      await this.storage.put("operationLogs", this.storageBuffer);
    } catch (error) {
      console.error(`[Logger-存储] 写入失败: ${error.message}`);
    }
  }

  shouldLog(level) {
    return this.levels[level] <= this.currentLevel;
  }

  formatTimestamp() {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, "0");
    const day = String(now.getDate()).padStart(2, "0");
    const hours = String(now.getHours()).padStart(2, "0");
    const minutes = String(now.getMinutes()).padStart(2, "0");
    const seconds = String(now.getSeconds()).padStart(2, "0");
    return `[${year}-${month}-${day} ${hours}:${minutes}:${seconds}]`;
  }

  // 中文日志级别映射
  getChineseLevel(level) {
    const levelMap = {
      error: "错误",
      warn: "警告",
      info: "信息",
      debug: "调试",
    };
    return levelMap[level] || level.toUpperCase();
  }

  createLogMessage(level, ...args) {
    const timestamp = this.formatTimestamp();
    const chineseLevel = this.getChineseLevel(level);
    const message = args
      .map((arg) =>
        typeof arg === "object" ? JSON.stringify(arg) : String(arg)
      )
      .join(" ");

    return `${timestamp} [${chineseLevel}] : ${message}`;
  }

  error(...args) {
    if (this.shouldLog("error")) {
      const message = this.createLogMessage("error", ...args);
      console.error(message);
      this.writeToStorage("error", message);
    }
  }

  warn(...args) {
    if (this.shouldLog("warn")) {
      const message = this.createLogMessage("warn", ...args);
      console.warn(message);
      this.writeToStorage("warn", message);
    }
  }

  info(...args) {
    if (this.shouldLog("info")) {
      const message = this.createLogMessage("info", ...args);
      console.log(message);
      this.writeToStorage("info", message);
    }
  }

  debug(...args) {
    if (this.shouldLog("debug")) {
      const message = this.createLogMessage("debug", ...args);
      console.log(message);
      this.writeToStorage("debug", message);
    }
  }
}

// 设置待处理的 storage 引用
export async function setPendingStorage(storage) {
  pendingStorage = storage;
  // 如果 logger 已经初始化但没有 storage，立即设置
  if (globalLogger && !globalLogger.storage) {
    await globalLogger.setStorage(storage);
  }
}

// 日志初始化函数
async function autoInitialize() {
  if (isInitialized) return;

  // 从 RelayRoom 获取环境变量
  let env = { LOG_LEVEL: "warn" };
  let foundSource = "默认值";

  // 检查 RelayRoom 实例是否存在
  if (
    typeof globalThis !== "undefined" &&
    globalThis.RelayRoomInstance &&
    globalThis.RelayRoomInstance.env
  ) {
    env = globalThis.RelayRoomInstance.env;
    foundSource = "RelayRoom.env";
  }

  globalLogger = new Logger(env);
  if (pendingStorage) {
    await globalLogger.setStorage(pendingStorage);
  }
  logger.globalLogger = globalLogger;
  isInitialized = true;
}

// 导出全局logger，自动初始化
export const logger = {
  globalLogger: null,

  error: async (...args) => {
    if (!isInitialized) await autoInitialize();
    if (globalLogger) {
      globalLogger.error(...args);
    }
  },
  warn: async (...args) => {
    if (!isInitialized) await autoInitialize();
    if (globalLogger) {
      globalLogger.warn(...args);
    }
  },
  info: async (...args) => {
    if (!isInitialized) await autoInitialize();
    if (globalLogger) {
      globalLogger.info(...args);
    }
  },
  debug: async (...args) => {
    if (!isInitialized) await autoInitialize();
    if (globalLogger) {
      globalLogger.debug(...args);
    }
  },
};

// 手动设置全局日志级别
export function setGlobalLogLevel(level) {
  // console.log(`[Logger] 日志级别设置为: ${level}`);
  if (typeof globalThis !== "undefined") {
    globalThis.LOG_LEVEL = level;
  }
  // 重新初始化
  globalLogger = new Logger({ LOG_LEVEL: level });
  isInitialized = true;
}
