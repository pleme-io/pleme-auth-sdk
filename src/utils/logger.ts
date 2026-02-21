/**
 * Simple Console Logger
 *
 * Lightweight logging utility for auth-sdk package
 * Can be replaced with more sophisticated logging in production
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error'
export type LogContext = string

interface LogMetadata {
  [key: string]: unknown
}

/**
 * Logger class with context support
 */
class Logger {
  private minLevel: LogLevel

  constructor(minLevel: LogLevel = 'info') {
    this.minLevel = minLevel
  }

  private shouldLog(level: LogLevel): boolean {
    const levels: LogLevel[] = ['debug', 'info', 'warn', 'error']
    const minLevelIndex = levels.indexOf(this.minLevel)
    const currentLevelIndex = levels.indexOf(level)
    return currentLevelIndex >= minLevelIndex
  }

  private formatMessage(
    level: LogLevel,
    message: string,
    metadata?: LogMetadata,
    context?: LogContext
  ): string {
    const timestamp = new Date().toISOString()
    const contextStr = context ? `[${context}]` : ''
    const metadataStr = metadata ? ` ${JSON.stringify(metadata)}` : ''
    return `${timestamp} ${level.toUpperCase()} ${contextStr} ${message}${metadataStr}`
  }

  debug(message: string, metadata?: LogMetadata, context?: LogContext): void {
    if (this.shouldLog('debug')) {
      console.debug(this.formatMessage('debug', message, metadata, context))
    }
  }

  info(message: string, metadata?: LogMetadata, context?: LogContext): void {
    if (this.shouldLog('info')) {
      console.info(this.formatMessage('info', message, metadata, context))
    }
  }

  warn(message: string, metadata?: LogMetadata, context?: LogContext): void {
    if (this.shouldLog('warn')) {
      console.warn(this.formatMessage('warn', message, metadata, context))
    }
  }

  error(message: string, metadata?: LogMetadata, context?: LogContext): void {
    if (this.shouldLog('error')) {
      console.error(this.formatMessage('error', message, metadata, context))
    }
  }

  /**
   * Set minimum log level
   */
  setLevel(level: LogLevel): void {
    this.minLevel = level
  }

  /**
   * Get current log level
   */
  getLevel(): LogLevel {
    return this.minLevel
  }
}

/**
 * Default logger instance
 * Set to 'info' in production, 'debug' in development
 */
export const logger: Logger = new Logger(
  process.env.NODE_ENV === 'production' ? 'info' : 'debug'
)

/**
 * Create a custom logger with specific level
 */
export function createLogger(level: LogLevel = 'info'): Logger {
  return new Logger(level)
}
