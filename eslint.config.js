import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      'dist',
      'node_modules',
      'coverage',
      'playwright-report',
      'test-results',
      'scripts', // plain node build helper, not part of the app
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      globals: {
        document: 'readonly',
        window: 'readonly',
        localStorage: 'readonly',
        crypto: 'readonly',
        history: 'readonly',
        Node: 'readonly',
        HTMLElement: 'readonly',
        HTMLButtonElement: 'readonly',
        HTMLDetailsElement: 'readonly',
        Event: 'readonly',
        EventListener: 'readonly',
        TextEncoder: 'readonly',
        location: 'readonly',
        navigator: 'readonly',
        getComputedStyle: 'readonly',
        setTimeout: 'readonly',
        URLSearchParams: 'readonly',
      },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      // The teaching code uses the reference library's `any`-typed `__tests` surface
      // deliberately, narrowed at the import site; allow explicit any there.
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
);
