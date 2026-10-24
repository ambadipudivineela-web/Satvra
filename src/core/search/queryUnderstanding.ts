/**
 * SATVRA Query Understanding & Typo Tolerance Engine
 * 
 * Provides:
 * - Damerau-Levenshtein typo correction for missing, transposed, or misspelled letters.
 * - Common abbreviation & synonym expansion (e.g. "govt" -> "government", "tut" -> "tutorial").
 * - High-confidence "Did you mean: ..." query suggestions.
 * - Related search suggestions based on semantic domain and query tokens.
 */

// Domain dictionary containing standard web, programming, technology, civic, media, and general search vocabulary
const VOCABULARY: Record<string, string> = {
  // Programming & Tech
  'python': 'Python',
  'javascript': 'JavaScript',
  'typescript': 'TypeScript',
  'react': 'React',
  'angular': 'Angular',
  'vue': 'Vue',
  'node': 'Node.js',
  'express': 'Express',
  'django': 'Django',
  'flask': 'Flask',
  'html': 'HTML',
  'css': 'CSS',
  'sql': 'SQL',
  'nosql': 'NoSQL',
  'mongodb': 'MongoDB',
  'postgres': 'PostgreSQL',
  'postgresql': 'PostgreSQL',
  'mysql': 'MySQL',
  'database': 'database',
  'databases': 'databases',
  'interview': 'interview',
  'interviews': 'interviews',
  'question': 'question',
  'questions': 'questions',
  'answer': 'answer',
  'answers': 'answers',
  'tutorial': 'tutorial',
  'tutorials': 'tutorials',
  'guide': 'guide',
  'guides': 'guides',
  'documentation': 'documentation',
  'docs': 'documentation',
  'course': 'course',
  'courses': 'courses',
  'beginner': 'beginner',
  'beginners': 'beginners',
  'advanced': 'advanced',
  'intermediate': 'intermediate',
  'programming': 'programming',
  'developer': 'developer',
  'development': 'development',
  'software': 'software',
  'algorithm': 'algorithm',
  'algorithms': 'algorithms',
  'download': 'download',
  'install': 'install',
  'installation': 'installation',
  'setup': 'setup',
  'github': 'GitHub',
  'stackoverflow': 'Stack Overflow',
  'api': 'API',
  'backend': 'backend',
  'frontend': 'frontend',
  'fullstack': 'fullstack',
  'cybersecurity': 'cybersecurity',
  'security': 'security',
  'encryption': 'encryption',
  'browser': 'browser',
  'extension': 'extension',

  // Major Platforms & Entities
  'youtube': 'YouTube',
  'google': 'Google',
  'wikipedia': 'Wikipedia',
  'amazon': 'Amazon',
  'netflix': 'Netflix',
  'spotify': 'Spotify',
  'linkedin': 'LinkedIn',
  'twitter': 'Twitter',
  'reddit': 'Reddit',
  'github.com': 'GitHub',
  'imdb': 'IMDb',

  // Media, Entertainment & Everyday
  'movie': 'movie',
  'movies': 'movies',
  'cinema': 'cinema',
  'film': 'film',
  'films': 'films',
  'music': 'music',
  'song': 'song',
  'songs': 'songs',
  'video': 'video',
  'videos': 'videos',
  'news': 'news',
  'weather': 'weather',
  'forecast': 'forecast',
  'sports': 'sports',
  'technology': 'technology',
  'education': 'education',
  'university': 'university',
  'college': 'college',
  'shopping': 'shopping',
  'review': 'review',
  'reviews': 'reviews',
  'recipe': 'recipe',
  'recipes': 'recipes',
  'health': 'health',
  'fitness': 'fitness',
  'travel': 'travel',
  'hotel': 'hotel',
  'flight': 'flight',
  'flights': 'flights',

  // Civic, Government, Careers & Official
  'government': 'government',
  'govt': 'government',
  'official': 'official',
  'portal': 'portal',
  'service': 'service',
  'services': 'services',
  'recruitment': 'recruitment',
  'vacancy': 'vacancy',
  'vacancies': 'vacancies',
  'notification': 'notification',
  'notifications': 'notifications',
  'notif': 'notification',
  'job': 'job',
  'jobs': 'jobs',
  'career': 'career',
  'careers': 'careers',
  'employment': 'employment',
  'exam': 'exam',
  'exams': 'exams',
  'examination': 'examination',
  'results': 'results',
  'result': 'result',
  'syllabus': 'syllabus',
  'eligibility': 'eligibility',
  'application': 'application',
  'apply': 'apply',
  'online': 'online',
  'form': 'form',
  'passport': 'passport',
  'renewal': 'renewal',
  'renew': 'renew',
  'visa': 'visa',
  'appointment': 'appointment',
  'license': 'license',
  'refund': 'refund',
  'tax': 'tax',
  'taxes': 'taxes',
  'internal': 'internal',
  'revenue': 'revenue',
  'federal': 'federal',
  'state': 'state',
  'student': 'student',
  'aid': 'aid',
  'financial': 'financial',
};

// Known common phonetic and typing typos mapped directly for instant O(1) resolution
const DIRECT_TYPO_MAP: Record<string, string> = {
  'pythn': 'python',
  'pyton': 'python',
  'pythan': 'python',
  'pythone': 'python',
  'tutrial': 'tutorial',
  'tutrials': 'tutorials',
  'toturial': 'tutorial',
  'tutoria': 'tutorial',
  'turtorial': 'tutorial',
  'begginer': 'beginner',
  'begginers': 'beginners',
  'beginer': 'beginner',
  'beginers': 'beginners',
  'beggining': 'beginning',
  'youtub': 'youtube',
  'you-tube': 'youtube',
  'yutube': 'youtube',
  'youtbe': 'youtube',
  'youtue': 'youtube',
  'u-tube': 'youtube',
  'intervew': 'interview',
  'intervews': 'interviews',
  'intrview': 'interview',
  'queston': 'question',
  'questons': 'questions',
  'qestions': 'questions',
  'answr': 'answer',
  'answrs': 'answers',
  'documntation': 'documentation',
  'documenation': 'documentation',
  'programing': 'programming',
  'progamming': 'programming',
  'devloper': 'developer',
  'developper': 'developer',
  'algoritm': 'algorithm',
  'datbase': 'database',
  'databse': 'database',
  'postgress': 'postgresql',
  'postgre': 'postgresql',
  'javascrip': 'javascript',
  'javscript': 'javascript',
  'typscript': 'typescript',
  'notfication': 'notification',
  'notfications': 'notifications',
  'notifcation': 'notification',
  'notifcations': 'notifications',
  'notificaton': 'notification',
  'notificatons': 'notifications',
  'recrutment': 'recruitment',
  'recuitment': 'recruitment',
  'recrutement': 'recruitment',
  'vacancys': 'vacancies',
  'vacancies': 'vacancies',
  'vacency': 'vacancy',
  'vacencys': 'vacancies',
  'goverment': 'government',
  'governmnet': 'government',
  'govenment': 'government',
  'govment': 'government',
  'gov': 'government',
  'govt': 'government',
  'oficial': 'official',
  'offical': 'official',
  'offcial': 'official',
  'portel': 'portal',
  'aplication': 'application',
  'aplicaton': 'application',
  'pasport': 'passport',
  'passsport': 'passport',
  'renwal': 'renewal',
  'renwel': 'renewal',
  'apointment': 'appointment',
  'licence': 'license',
  'lisence': 'license',
  'movi': 'movie',
  'movis': 'movies',
  'moive': 'movie',
  'moives': 'movies',
  'vedio': 'video',
  'vedios': 'videos',
  'technolgy': 'technology',
  'techology': 'technology',
  'educaton': 'education',
  'universiti': 'university',
};

export interface QueryCorrectionResult {
  originalQuery: string;
  correctedQuery?: string;
  hasTypoCorrection: boolean;
  tokens: string[];
  correctedTokens: string[];
  relatedQueries: string[];
}

/**
 * Calculates Damerau-Levenshtein distance between two strings
 * Handles substitutions, insertions, deletions, and adjacent character transpositions.
 */
export function damerauLevenshtein(a: string, b: string): number {
  const la = a.length;
  const lb = b.length;
  if (la === 0) return lb;
  if (lb === 0) return la;

  const d: number[][] = Array.from({ length: la + 1 }, () => Array(lb + 1).fill(0));

  for (let i = 0; i <= la; i++) d[i][0] = i;
  for (let j = 0; j <= lb; j++) d[0][j] = j;

  for (let i = 1; i <= la; i++) {
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(
        d[i - 1][j] + 1, // deletion
        d[i][j - 1] + 1, // insertion
        d[i - 1][j - 1] + cost // substitution
      );

      // Transposition
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }

  return d[la][lb];
}

/**
 * Corrects an individual token using dictionary and edit distance
 */
export function correctToken(rawToken: string): { corrected: string; changed: boolean } {
  const lower = rawToken.toLowerCase().replace(/[^a-z0-9_.-]/g, '');
  if (!lower || lower.length < 3) {
    return { corrected: rawToken, changed: false };
  }

  // 1. Direct O(1) typo dictionary lookup
  if (DIRECT_TYPO_MAP[lower]) {
    const canonical = VOCABULARY[DIRECT_TYPO_MAP[lower]] || DIRECT_TYPO_MAP[lower];
    return { corrected: canonical, changed: true };
  }

  // 2. Exact vocabulary match
  if (VOCABULARY[lower]) {
    return { corrected: VOCABULARY[lower], changed: false };
  }

  // 3. Fuzzy match against vocabulary if length >= 4
  if (lower.length >= 4) {
    let bestMatch: string | null = null;
    let minDistance = 999;
    const maxAllowedDist = lower.length >= 7 ? 2 : 1;

    for (const word of Object.keys(VOCABULARY)) {
      if (Math.abs(word.length - lower.length) > maxAllowedDist) continue;
      // Skip if first characters are completely different for short words
      if (lower.length <= 5 && word[0] !== lower[0]) continue;

      const dist = damerauLevenshtein(lower, word);
      if (dist < minDistance && dist <= maxAllowedDist) {
        minDistance = dist;
        bestMatch = word;
      }
    }

    if (bestMatch && minDistance <= maxAllowedDist) {
      return { corrected: VOCABULARY[bestMatch] || bestMatch, changed: true };
    }
  }

  return { corrected: rawToken, changed: false };
}

/**
 * Analyzes and corrects a full search query, preserving proper formatting,
 * generating intelligent related queries, and offering suggested corrections.
 */
export function understandQuery(query: string): QueryCorrectionResult {
  const trimmed = (query || '').trim();
  if (!trimmed) {
    return {
      originalQuery: '',
      hasTypoCorrection: false,
      tokens: [],
      correctedTokens: [],
      relatedQueries: [],
    };
  }

  const rawTokens = trimmed.split(/\s+/);
  const correctedTokens: string[] = [];
  let anyChanged = false;

  for (const token of rawTokens) {
    const res = correctToken(token);
    correctedTokens.push(res.corrected);
    if (res.changed) {
      anyChanged = true;
    }
  }

  const correctedPhrase = correctedTokens.join(' ');
  const hasTypoCorrection = anyChanged && correctedPhrase.toLowerCase() !== trimmed.toLowerCase();

  // Generate contextual related searches
  const relatedQueries = generateRelatedQueries(hasTypoCorrection ? correctedPhrase : trimmed);

  return {
    originalQuery: trimmed,
    correctedQuery: hasTypoCorrection ? correctedPhrase : undefined,
    hasTypoCorrection,
    tokens: rawTokens,
    correctedTokens,
    relatedQueries,
  };
}

/**
 * Generates related queries based on semantic domain and query topics
 */
export function generateRelatedQueries(query: string): string[] {
  const lower = query.toLowerCase();
  const suggestions: string[] = [];

  if (lower.includes('python')) {
    suggestions.push('Python official documentation');
    suggestions.push('Python practice exercises with solutions');
    suggestions.push('Python data science tutorials');
    suggestions.push('Python automation scripts for beginners');
  } else if (lower.includes('sql')) {
    suggestions.push('SQL interview questions for experienced developers');
    suggestions.push('SQL query practice LeetCode');
    suggestions.push('PostgreSQL tutorial for beginners');
    suggestions.push('Database indexing and optimization guide');
  } else if (lower.includes('youtube')) {
    suggestions.push('YouTube Music web player');
    suggestions.push('YouTube Studio creator dashboard');
    suggestions.push('YouTube trending videos today');
  } else if (lower.includes('job') || lower.includes('government') || lower.includes('recruitment')) {
    suggestions.push('USAJOBS federal recruitment portal');
    suggestions.push('State civil service examinations notice');
    suggestions.push('Upcoming public sector job vacancies');
    suggestions.push('Government employment application guide');
  } else if (lower.includes('movie') || lower.includes('film')) {
    suggestions.push('Top rated movies of 2026 IMDb');
    suggestions.push('New movie trailers this week');
    suggestions.push('Award winning independent films');
  } else if (lower.includes('react') || lower.includes('javascript') || lower.includes('typescript')) {
    suggestions.push('Modern React hooks reference guide');
    suggestions.push('TypeScript handbook official');
    suggestions.push('Fullstack web development roadmap');
  } else {
    // General expansion
    suggestions.push(`${query} official guide`);
    suggestions.push(`${query} documentation and examples`);
    suggestions.push(`${query} latest updates and news`);
  }

  return suggestions.slice(0, 4);
}
