/**
 * Vitest Test Setup
 *
 * Configures testing environment with mocks for browser APIs
 * and common test utilities.
 */

import '@testing-library/jest-dom'
import { vi } from 'vitest'

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {}
  return {
    getItem: vi.fn((key: string) => store[key] ?? null),
    setItem: vi.fn((key: string, value: string) => {
      store[key] = value
    }),
    removeItem: vi.fn((key: string) => {
      delete store[key]
    }),
    clear: vi.fn(() => {
      store = {}
    }),
    get length() {
      return Object.keys(store).length
    },
    key: vi.fn((index: number) => Object.keys(store)[index] ?? null),
  }
})()

Object.defineProperty(globalThis, 'localStorage', {
  value: localStorageMock,
  writable: true,
})

// Mock sessionStorage
Object.defineProperty(globalThis, 'sessionStorage', {
  value: localStorageMock,
  writable: true,
})

// Mock atob/btoa for JWT parsing
if (typeof globalThis.atob === 'undefined') {
  globalThis.atob = (data: string) => Buffer.from(data, 'base64').toString('utf8')
}

if (typeof globalThis.btoa === 'undefined') {
  globalThis.btoa = (data: string) => Buffer.from(data, 'utf8').toString('base64')
}

// Clear mocks between tests
beforeEach(() => {
  vi.clearAllMocks()
  localStorageMock.clear()
})
