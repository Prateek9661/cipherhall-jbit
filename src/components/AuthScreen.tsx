import React, { useState } from 'react';
import { Eye, EyeOff, KeyRound, Loader2, Lock, ShieldCheck } from 'lucide-react';
import { loginUserApi, registerUserApi } from '../services/vaultApi';
import type { UserProfile, UserRole } from '../types/vault';
import {
  evaluatePassphraseStrength,
  generateUserKeyBundle,
  importPublicKeyFromSpkiBase64,
  INSTITUTION_NAME,
  unlockPrivateKeyWithPassphrase,
  validateAuthForm,
} from '../utils/cryptoEngine';

interface AuthScreenProps {
  onAuthenticated: (session: { user: UserProfile; token: string }) => void;
}

export function AuthScreen({ onAuthenticated }: AuthScreenProps) {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<UserRole>('Student');
  const [department, setDepartment] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [statusText, setStatusText] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);
  const [errors, setErrors] = useState<
    Partial<Record<'name' | 'email' | 'password' | 'passphrase', string>>
  >({});

  const strength = evaluatePassphraseStrength(passphrase);

  const handleModeSwitch = (nextMode: 'login' | 'register') => {
    setMode(nextMode);
    setErrors({});
    setAuthError(null);
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setAuthError(null);
    const validation = validateAuthForm({
      mode,
      name,
      email,
      password,
      role,
      passphrase,
    });

    if (!validation.valid) {
      setErrors(validation.errors);
      return;
    }

    setIsSubmitting(true);
    try {
      const normalizedEmail = email.trim().toLowerCase();
      const unlockedAt = new Date().toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
      });

      if (mode === 'register') {
        setStatusText('Generating RSA-OAEP-2048 Key Pair…');
        const keyMaterial = await generateUserKeyBundle(passphrase);

        setStatusText('Creating Encrypted Campus Account…');
        const response = await registerUserApi({
          name: name.trim(),
          email: normalizedEmail,
          password,
          role,
          department: department.trim() || undefined,
          keyFingerprint: keyMaterial.keyFingerprint,
          publicKeySpkiBase64: keyMaterial.publicKeySpkiBase64,
          protectedPrivateKey: keyMaterial.protectedPrivateKey,
        });

        onAuthenticated({
          token: response.token,
          user: {
            id: response.user.id,
            name: response.user.name,
            email: response.user.email,
            role: response.user.role,
            department: response.user.department,
            keyFingerprint: response.user.keyFingerprint,
            publicKeySpkiBase64: response.user.publicKeySpkiBase64,
            publicKey: keyMaterial.publicKey,
            privateKey: keyMaterial.privateKey,
            protectedPrivateKey: response.user.protectedPrivateKey,
            vaultUnlockedAt: unlockedAt,
          },
        });
      } else {
        setStatusText('Verifying Campus Credentials…');
        const response = await loginUserApi({
          email: normalizedEmail,
          password,
        });

        setStatusText('Unlocking Local RSA-2048 Private Key…');
        let unlockedPrivateKey: CryptoKey;
        try {
          unlockedPrivateKey = await unlockPrivateKeyWithPassphrase(
            response.user.protectedPrivateKey,
            passphrase
          );
        } catch {
          throw new Error(
            'Incorrect Vault Passphrase. Your local private key could not be unlocked.'
          );
        }

        const importedPublicKey = await importPublicKeyFromSpkiBase64(
          response.user.publicKeySpkiBase64
        );

        onAuthenticated({
          token: response.token,
          user: {
            id: response.user.id,
            name: response.user.name,
            email: response.user.email,
            role: response.user.role,
            department: response.user.department,
            keyFingerprint: response.user.keyFingerprint,
            publicKeySpkiBase64: response.user.publicKeySpkiBase64,
            publicKey: importedPublicKey,
            privateKey: unlockedPrivateKey,
            protectedPrivateKey: response.user.protectedPrivateKey,
            vaultUnlockedAt: unlockedAt,
          },
        });
      }
    } catch (err) {
      setAuthError(
        err instanceof Error
          ? err.message
          : 'Authentication failed. Please check your credentials and try again.'
      );
    } finally {
      setIsSubmitting(false);
      setStatusText('');
    }
  };

  const strengthBarColors: Record<number, string> = {
    0: 'bg-slate-800',
    1: 'bg-rose-500',
    2: 'bg-amber-500',
    3: 'bg-blue-500',
    4: 'bg-emerald-500',
  };

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col lg:flex-row">
      {/* Left Institutional Overview Column */}
      <section className="lg:w-[46%] xl:w-[48%] bg-[#0E1420] border-b lg:border-b-0 lg:border-r border-slate-800/80 px-6 py-10 sm:px-12 lg:px-14 lg:py-16 flex flex-col justify-between">
        <div>
          <div className="flex items-center gap-2.5 text-slate-100">
            <div className="h-9 w-9 rounded-lg bg-blue-600/15 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <ShieldCheck className="h-5 w-5" aria-hidden="true" />
            </div>
            <span className="font-display text-lg font-bold tracking-tight whitespace-nowrap">
              CipherHall
            </span>
          </div>

          <div className="mt-12 lg:mt-20 max-w-lg">
            <p className="text-sm font-medium text-blue-400">{INSTITUTION_NAME}</p>
            <h1 className="mt-3 font-display text-3xl sm:text-4xl font-bold tracking-tight text-slate-50 leading-tight [text-wrap:balance]">
              Zero-knowledge file vault and encrypted campus messaging.
            </h1>
            <p className="mt-4 text-base text-slate-400 leading-relaxed">
              Your files and messages are encrypted on your device before leaving your browser.
              Not even campus IT admins can read them.
            </p>
          </div>

          <dl className="mt-10 lg:mt-14 max-w-lg divide-y divide-slate-800/80 border-t border-b border-slate-800/80">
            <div className="py-4 flex items-baseline justify-between gap-4">
              <dt className="text-sm font-medium text-slate-300">Symmetric Cipher</dt>
              <dd className="font-mono text-sm text-slate-400 tabular-nums">
                AES-256-GCM · 12-byte IV
              </dd>
            </div>
            <div className="py-4 flex items-baseline justify-between gap-4">
              <dt className="text-sm font-medium text-slate-300">Key Encapsulation</dt>
              <dd className="font-mono text-sm text-slate-400 tabular-nums">
                RSA-OAEP-2048 · SHA-256
              </dd>
            </div>
            <div className="py-4 flex items-baseline justify-between gap-4">
              <dt className="text-sm font-medium text-slate-300">Key Protection</dt>
              <dd className="font-mono text-sm text-slate-400 tabular-nums">
                PBKDF2-SHA256 · 100k iter
              </dd>
            </div>
          </dl>
        </div>

        <p className="mt-10 text-xs text-slate-500">
          Private keys are generated via Web Crypto API and wrapped locally with your Vault
          Passphrase—never leaving your browser unencrypted.
        </p>
      </section>

      {/* Right Authentication Form Column */}
      <main className="flex-1 flex items-center justify-center px-6 py-10 sm:px-10 lg:px-16">
        <div className="w-full max-w-md">
          {/* Login / Register Toggle */}
          <div
            role="tablist"
            aria-label="Authentication mode"
            className="grid grid-cols-2 p-1 rounded-lg bg-[#111824] border border-slate-800/90"
          >
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'login'}
              onClick={() => handleModeSwitch('login')}
              className={`py-2.5 px-4 text-sm font-medium rounded-md transition-colors whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                mode === 'login'
                  ? 'bg-slate-800 text-slate-50 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'register'}
              onClick={() => handleModeSwitch('register')}
              className={`py-2.5 px-4 text-sm font-medium rounded-md transition-colors whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                mode === 'register'
                  ? 'bg-slate-800 text-slate-50 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Create Account
            </button>
          </div>

          <div className="mt-6">
            <h2 className="font-display text-2xl font-semibold tracking-tight text-slate-50">
              {mode === 'login' ? 'Unlock your academic vault' : 'Register campus vault key'}
            </h2>
            <p className="mt-1.5 text-sm text-slate-400">
              {mode === 'login'
                ? 'Sign in with your registered institute account and enter your Vault Passphrase to unwrap your local RSA private key.'
                : 'Create your Student or Faculty account and generate a personal passphrase-protected RSA-2048 keypair.'}
            </p>
          </div>

          <form onSubmit={handleSubmit} noValidate className="mt-6 space-y-4">
            {/* Full Name (Registration only) */}
            {mode === 'register' && (
              <div>
                <label
                  htmlFor="auth-name"
                  className="block text-sm font-medium text-slate-300 mb-1.5"
                >
                  Full Name
                </label>
                <input
                  id="auth-name"
                  type="text"
                  autoComplete="name"
                  value={name}
                  onChange={(e) => {
                    setName(e.target.value);
                    if (errors.name) setErrors((prev) => ({ ...prev, name: undefined }));
                  }}
                  placeholder="Enter your full name"
                  aria-invalid={Boolean(errors.name)}
                  className="w-full h-11 px-3.5 rounded-lg bg-[#111824] border border-slate-800 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
                />
                {errors.name && (
                  <p role="alert" className="mt-1.5 text-xs text-rose-400">
                    {errors.name}
                  </p>
                )}
              </div>
            )}

            {/* Email */}
            <div>
              <label
                htmlFor="auth-email"
                className="block text-sm font-medium text-slate-300 mb-1.5"
              >
                Institute Email
              </label>
              <input
                id="auth-email"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  if (errors.email) setErrors((prev) => ({ ...prev, email: undefined }));
                }}
                placeholder="name@jbitdoon.edu.in"
                aria-invalid={Boolean(errors.email)}
                className="w-full h-11 px-3.5 rounded-lg bg-[#111824] border border-slate-800 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
              />
              {errors.email && (
                <p role="alert" className="mt-1.5 text-xs text-rose-400">
                  {errors.email}
                </p>
              )}
            </div>

            {/* Password */}
            <div>
              <label
                htmlFor="auth-password"
                className="block text-sm font-medium text-slate-300 mb-1.5"
              >
                Password
              </label>
              <div className="relative">
                <input
                  id="auth-password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (errors.password)
                      setErrors((prev) => ({ ...prev, password: undefined }));
                  }}
                  placeholder="Minimum 8 characters"
                  aria-invalid={Boolean(errors.password)}
                  className="w-full h-11 pl-3.5 pr-11 rounded-lg bg-[#111824] border border-slate-800 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  className="absolute right-2 top-1/2 -translate-y-1/2 p-2 text-slate-400 hover:text-slate-200 rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" aria-hidden="true" />
                  ) : (
                    <Eye className="h-4 w-4" aria-hidden="true" />
                  )}
                </button>
              </div>
              {errors.password && (
                <p role="alert" className="mt-1.5 text-xs text-rose-400">
                  {errors.password}
                </p>
              )}
            </div>

            {/* Role Selector & Department (Registration only) */}
            {mode === 'register' && (
              <>
                <fieldset>
                  <legend className="block text-sm font-medium text-slate-300 mb-1.5">
                    Academic Role
                  </legend>
                  <div className="grid grid-cols-2 gap-3">
                    {(['Student', 'Faculty'] as UserRole[]).map((option) => {
                      const isSelected = role === option;
                      return (
                        <button
                          key={option}
                          type="button"
                          onClick={() => setRole(option)}
                          aria-pressed={isSelected}
                          className={`h-11 px-4 rounded-lg border text-sm font-medium transition-colors flex items-center justify-center gap-2 whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                            isSelected
                              ? 'bg-blue-600/15 border-blue-500 text-blue-300'
                              : 'bg-[#111824] border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                          }`}
                        >
                          <span>{option}</span>
                        </button>
                      );
                    })}
                  </div>
                </fieldset>

                <div>
                  <label
                    htmlFor="auth-department"
                    className="block text-sm font-medium text-slate-300 mb-1.5"
                  >
                    Department{' '}
                    <span className="text-xs font-normal text-slate-500">(optional)</span>
                  </label>
                  <input
                    id="auth-department"
                    type="text"
                    value={department}
                    onChange={(e) => setDepartment(e.target.value)}
                    placeholder="e.g. Computer Science & Engineering"
                    className="w-full h-11 px-3.5 rounded-lg bg-[#111824] border border-slate-800 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
                  />
                </div>
              </>
            )}

            {/* Vault Passphrase */}
            <div className="pt-2 border-t border-slate-800/80">
              <div className="flex items-center justify-between mb-1.5">
                <label
                  htmlFor="auth-passphrase"
                  className="flex items-center gap-1.5 text-sm font-medium text-slate-200"
                >
                  <KeyRound className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
                  <span>Vault Passphrase</span>
                </label>
                {passphrase.length > 0 && (
                  <span className="text-xs font-mono text-slate-400">{strength.label}</span>
                )}
              </div>
              <div className="relative">
                <input
                  id="auth-passphrase"
                  type={showPassphrase ? 'text' : 'password'}
                  value={passphrase}
                  onChange={(e) => {
                    setPassphrase(e.target.value);
                    if (errors.passphrase)
                      setErrors((prev) => ({ ...prev, passphrase: undefined }));
                  }}
                  placeholder={
                    mode === 'register'
                      ? 'Create a passphrase to protect your RSA private key'
                      : 'Enter your passphrase to unlock your RSA private key'
                  }
                  aria-invalid={Boolean(errors.passphrase)}
                  className="w-full h-11 pl-3.5 pr-11 rounded-lg bg-[#111824] border border-slate-800 font-mono text-sm text-slate-100 placeholder:font-sans placeholder:text-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPassphrase((prev) => !prev)}
                  aria-label={
                    showPassphrase ? 'Hide vault passphrase' : 'Show vault passphrase'
                  }
                  className="absolute right-2 top-1/2 -translate-y-1/2 p-2 text-slate-400 hover:text-slate-200 rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                >
                  {showPassphrase ? (
                    <EyeOff className="h-4 w-4" aria-hidden="true" />
                  ) : (
                    <Eye className="h-4 w-4" aria-hidden="true" />
                  )}
                </button>
              </div>
              {/* Strength meter */}
              <div className="mt-2 grid grid-cols-4 gap-1.5" aria-hidden="true">
                {[1, 2, 3, 4].map((segment) => (
                  <div
                    key={segment}
                    className={`h-1 rounded-full transition-colors ${
                      strength.score >= segment
                        ? strengthBarColors[strength.score]
                        : 'bg-slate-800'
                    }`}
                  />
                ))}
              </div>
              <p className="mt-1.5 text-xs text-slate-500">
                Used locally with PBKDF2-SHA256 to protect and unlock your private key on this
                device. Never sent to the server.
              </p>
              {errors.passphrase && (
                <p role="alert" className="mt-1 text-xs text-rose-400">
                  {errors.passphrase}
                </p>
              )}
            </div>

            {authError && (
              <p
                role="alert"
                className="px-3.5 py-2.5 rounded-lg bg-rose-950/40 border border-rose-500/35 text-xs text-rose-300"
              >
                {authError}
              </p>
            )}

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full h-11 mt-2 px-4 rounded-lg bg-blue-600 hover:bg-blue-500 active:bg-blue-700 disabled:bg-blue-700/60 disabled:cursor-wait text-sm font-semibold text-white transition-colors flex items-center justify-center gap-2 whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 focus-visible:ring-offset-2 focus-visible:ring-offset-[#0B0F17]"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                  <span>{statusText || 'Processing…'}</span>
                </>
              ) : (
                <>
                  <Lock className="h-4 w-4" aria-hidden="true" />
                  <span>
                    {mode === 'login'
                      ? 'Unlock Private Key & Enter Vault'
                      : 'Generate Key & Create Account'}
                  </span>
                </>
              )}
            </button>
          </form>
        </div>
      </main>
    </div>
  );
}
