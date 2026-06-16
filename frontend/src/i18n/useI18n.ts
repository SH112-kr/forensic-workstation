import { useStore, type Language } from '../hooks/useStore';
import { en, translations, type TranslationKey } from './translations';

type Vars = Record<string, string | number>;

const getByPath = (obj: unknown, key: string): string | undefined => {
  const value = key.split('.').reduce<unknown>((acc, part) => {
    if (acc && typeof acc === 'object' && part in acc) {
      return (acc as Record<string, unknown>)[part];
    }
    return undefined;
  }, obj);
  return typeof value === 'string' ? value : undefined;
};

const interpolate = (template: string, vars?: Vars): string => {
  if (!vars) return template;
  return template.replace(/\{\{(\w+)\}\}/g, (_, name: string) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : `{{${name}}}`,
  );
};

export function useI18n() {
  const language = useStore((s) => s.language);
  const setLanguage = useStore((s) => s.setLanguage);

  const t = (key: TranslationKey, vars?: Vars): string => {
    const current = getByPath(translations[language], key);
    const fallback = getByPath(en, key);
    return interpolate(current ?? fallback ?? key, vars);
  };

  return { language, setLanguage: setLanguage as (language: Language) => void, t };
}
