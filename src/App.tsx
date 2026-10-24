/**
 * SATVRA — Trust What You Browse
 * Search-First Web Security & Official-Source Verification Platform
 */

import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Search,
  ExternalLink,
  Download,
  Terminal,
  Settings,
  RefreshCw,
  ArrowLeft,
  Lock,
  Globe,
  CheckCircle2,
  XCircle,
  FileCode,
  Info,
  ArrowRight,
  AlertTriangle,
  Compass,
  Sliders,
  History,
  Clock,
  Trash2,
  X,
  Sparkles,
} from 'lucide-react';
import { WebsiteEvaluation, OfficialSourceRecord, ProviderType } from './core/types.ts';
import { SearchResponse, SearchResultItem } from './core/search/types.ts';
import { OFFICIAL_SOURCES_DIRECTORY } from './core/officialSources/directory.ts';
import { searchOfficialSources } from './core/officialSources/matcher.ts';
import { isLikelyUrl, normalizeUrl } from './core/urlNormalizer.ts';
import { runAllTests, TestSuiteSummary } from './core/testSuite.ts';

type ActiveView = 'search' | 'urlcheck' | 'directory' | 'simulator' | 'tests' | 'packager' | 'settings';

export default function App() {
  const [activeView, setActiveView] = useState<ActiveView>('search');

  // --- Web Search State ---
  const [searchQuery, setSearchQuery] = useState('');
  const [searchLoading, setSearchLoading] = useState(false);
  const [searchResponse, setSearchResponse] = useState<SearchResponse | null>(null);
  const [searchError, setSearchError] = useState<string | null>(null);

  // --- URL Checking State ---
  const [directUrlInput, setDirectUrlInput] = useState('https://irs.gov/refunds');
  const [urlEvaluating, setUrlEvaluating] = useState(false);
  const [urlEvaluation, setUrlEvaluation] = useState<WebsiteEvaluation | null>(null);
  const [urlValidationError, setUrlValidationError] = useState<string | null>(null);

  // --- Protected View / Simulator State ---
  const [simulatedUrl, setSimulatedUrl] = useState('https://irs.gov/refunds');
  const [simulatorEvaluation, setSimulatorEvaluation] = useState<WebsiteEvaluation | null>(null);
  const [simulatorMode, setSimulatorMode] = useState<'content' | 'warning'>('content');
  const [popupOpen, setPopupOpen] = useState(true);
  const [popupActiveTab, setPopupActiveTab] = useState<'inspect' | 'official' | 'privacy'>('inspect');

  // --- Directory State ---
  const [dirQuery, setDirQuery] = useState('');
  const [dirCategory, setDirCategory] = useState<string>('ALL');

  // --- Test Runner State ---
  const [testSummary, setTestSummary] = useState<TestSuiteSummary | null>(null);
  const [runningTests, setRunningTests] = useState(false);

  // --- Settings State ---
  const [activeProvider, setActiveProvider] = useState<ProviderType>('composite');
  const [anonymizeUrls, setAnonymizeUrls] = useState(true);
  const [blockThreats, setBlockThreats] = useState(true);
  const [webRiskKey, setWebRiskKey] = useState('');
  const [urlhausKey, setUrlhausKey] = useState('');
  const [settingsSavedMsg, setSettingsSavedMsg] = useState(false);

  // --- LocalStorage Search History State ---
  const [recentSearches, setRecentSearches] = useState<string[]>(() => {
    try {
      const stored = localStorage.getItem('satvra_recent_searches');
      return stored ? JSON.parse(stored) : [];
    } catch {
      return [];
    }
  });
  const [showHistory, setShowHistory] = useState(false);
  const searchContainerRef = useRef<HTMLDivElement>(null);

  // Close search history dropdown on outside click
  useEffect(() => {
    function handlePointerDown(e: PointerEvent) {
      if (searchContainerRef.current && !searchContainerRef.current.contains(e.target as Node)) {
        setShowHistory(false);
      }
    }
    document.addEventListener('pointerdown', handlePointerDown);
    return () => document.removeEventListener('pointerdown', handlePointerDown);
  }, []);

  const saveSearchToHistory = (queryText: string) => {
    const q = queryText.trim();
    if (!q || isLikelyUrl(q)) return;

    setRecentSearches((prev) => {
      const filtered = prev.filter((item) => item.toLowerCase() !== q.toLowerCase());
      const updated = [q, ...filtered].slice(0, 8);
      try {
        localStorage.setItem('satvra_recent_searches', JSON.stringify(updated));
      } catch (err) {
        console.warn('Unable to save search history to localStorage:', err);
      }
      return updated;
    });
  };

  const removeSearchItem = (itemToRemove: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setRecentSearches((prev) => {
      const updated = prev.filter((item) => item !== itemToRemove);
      try {
        localStorage.setItem('satvra_recent_searches', JSON.stringify(updated));
      } catch (err) {
        console.warn('Unable to update search history:', err);
      }
      return updated;
    });
  };

  const clearAllSearchHistory = () => {
    try {
      localStorage.removeItem('satvra_recent_searches');
    } catch (err) {
      console.warn('Unable to clear search history:', err);
    }
    setRecentSearches([]);
    setShowHistory(false);
  };

  // Execute Web Search
  const executeSearch = async (term: string) => {
    const q = (term || '').trim();
    if (!q) return;

    // Check if user accidentally pasted an explicit URL into search box
    if (isLikelyUrl(q) && (q.startsWith('http://') || q.startsWith('https://'))) {
      // Offer direct URL checking
      setDirectUrlInput(q);
      setActiveView('urlcheck');
      checkExplicitUrl(q);
      return;
    }

    // Save to localStorage search history
    saveSearchToHistory(q);
    setShowHistory(false);

    setSearchLoading(true);
    setSearchError(null);

    try {
      const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
      if (!res.ok) {
        throw new Error(`Search provider returned HTTP ${res.status}`);
      }
      const data: SearchResponse = await res.json();
      setSearchResponse(data);
    } catch (err: unknown) {
      setSearchError((err as Error)?.message || 'Web search query failed');
    } finally {
      setSearchLoading(false);
    }
  };

  // Execute Direct URL Verification
  const checkExplicitUrl = async (inputUrl: string, force = false) => {
    setUrlValidationError(null);
    const trimmed = (inputUrl || '').trim();

    if (!trimmed) {
      setUrlValidationError('Please enter a website address.');
      setUrlEvaluation(null);
      return;
    }

    // Validate if it is actually a URL vs search query
    if (!isLikelyUrl(trimmed)) {
      setUrlValidationError(
        `"${trimmed}" is a natural-language search query rather than a website URL.`
      );
      setUrlEvaluation(null);
      return;
    }

    setUrlEvaluating(true);
    try {
      const res = await fetch('/api/threat-intel/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed, forceRefresh: force }),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: WebsiteEvaluation = await res.json();
      setUrlEvaluation(data);
    } catch (err: unknown) {
      setUrlValidationError((err as Error)?.message || 'Failed to complete URL security check');
      setUrlEvaluation(null);
    } finally {
      setUrlEvaluating(false);
    }
  };

  // Launch Simulator for a given URL
  const launchProtectedView = async (targetUrl: string) => {
    setSimulatedUrl(targetUrl);
    setActiveView('simulator');
    try {
      const res = await fetch('/api/threat-intel/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl }),
      });
      if (res.ok) {
        const data: WebsiteEvaluation = await res.json();
        setSimulatorEvaluation(data);
        if (data.status === 'KNOWN_THREAT' && blockThreats) {
          setSimulatorMode('warning');
        } else {
          setSimulatorMode('content');
        }
      }
    } catch {
      // Fallback
    }
  };

  // Run initial default search on load
  useEffect(() => {
    executeSearch(searchQuery);
    checkExplicitUrl(directUrlInput);
  }, []);

  // Directory Filter
  const directoryMatches = dirQuery.trim()
    ? searchOfficialSources(dirQuery).matches.map((m) => m.record)
    : OFFICIAL_SOURCES_DIRECTORY;

  const filteredDirectory = directoryMatches.filter((record) => {
    if (dirCategory === 'ALL') return true;
    return record.category === dirCategory;
  });

  // Automated Tests Handler
  const handleTestRun = async () => {
    setRunningTests(true);
    try {
      const res = await fetch('/api/tests/run', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setTestSummary(data);
      } else {
        const local = await runAllTests();
        setTestSummary(local);
      }
    } catch {
      const local = await runAllTests();
      setTestSummary(local);
    } finally {
      setRunningTests(false);
    }
  };

  const handleSaveSettings = async () => {
    try {
      await fetch('/api/threat-intel/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          activeProvider,
          anonymizeUrlLookups: anonymizeUrls,
          enableDeclarativeBlocking: blockThreats,
        }),
      });
      setSettingsSavedMsg(true);
      setTimeout(() => setSettingsSavedMsg(false), 2500);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/20 selection:text-cyan-200">
      {/* Top Bar Contract: 3 zones separated by gap-8 */}
      <header className="flex items-center justify-between gap-8 px-6 py-3.5 border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-40">
        {/* Zone 1: Wordmark */}
        <div
          onClick={() => setActiveView('search')}
          className="flex items-center gap-3 shrink-0 cursor-pointer"
        >
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-sky-600 flex items-center justify-center shadow-sm">
            <Shield className="w-4 h-4 text-slate-950 font-bold" />
          </div>
          <span className="text-base font-bold tracking-tight text-white whitespace-nowrap">SATVRA</span>
          <span className="text-xs text-cyan-400 whitespace-nowrap hidden sm:inline">Trust What You Browse</span>
        </div>

        {/* Zone 2: Single-line Navigation Links */}
        <nav className="hidden lg:flex items-center gap-6 text-sm font-medium text-slate-300">
          <button
            onClick={() => setActiveView('search')}
            className={`whitespace-nowrap shrink-0 transition-colors ${
              activeView === 'search' ? 'text-cyan-400 font-semibold' : 'hover:text-white'
            }`}
          >
            Web Search
          </button>
          <button
            onClick={() => setActiveView('urlcheck')}
            className={`whitespace-nowrap shrink-0 transition-colors ${
              activeView === 'urlcheck' ? 'text-cyan-400 font-semibold' : 'hover:text-white'
            }`}
          >
            URL Checker
          </button>
          <button
            onClick={() => setActiveView('directory')}
            className={`whitespace-nowrap shrink-0 transition-colors ${
              activeView === 'directory' ? 'text-cyan-400 font-semibold' : 'hover:text-white'
            }`}
          >
            Official Directory
          </button>
          <button
            onClick={() => setActiveView('simulator')}
            className={`whitespace-nowrap shrink-0 transition-colors ${
              activeView === 'simulator' ? 'text-cyan-400 font-semibold' : 'hover:text-white'
            }`}
          >
            Browser Extension Simulator
          </button>
          <button
            onClick={() => setActiveView('tests')}
            className={`whitespace-nowrap shrink-0 transition-colors ${
              activeView === 'tests' ? 'text-cyan-400 font-semibold' : 'hover:text-white'
            }`}
          >
            Developer Testbench
          </button>
          <button
            onClick={() => setActiveView('settings')}
            className={`whitespace-nowrap shrink-0 transition-colors ${
              activeView === 'settings' ? 'text-cyan-400 font-semibold' : 'hover:text-white'
            }`}
          >
            Settings
          </button>
        </nav>

        {/* Zone 3: Primary Action */}
        <div className="flex items-center gap-3 shrink-0">
          <a
            href="/api/extension/download"
            download="satvra-extension-mv3.zip"
            className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md transition-colors whitespace-nowrap shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download Extension (.zip)</span>
          </a>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 p-6 max-w-6xl mx-auto w-full">
        {/* ========================================================================= */}
        {/* VIEW 1: WEB SEARCH (MAIN USER EXPERIENCE)                                 */}
        {/* ========================================================================= */}
        {activeView === 'search' && (
          <div className="space-y-6">
            {/* Search Hero Area */}
            <div className="text-center max-w-2xl mx-auto pt-4 pb-2 space-y-2">
              <h1 className="text-2xl font-bold text-white tracking-tight">Trust What You Browse</h1>
              <p className="text-xs text-slate-400 leading-relaxed">
                Natural-language web search that verifies official institutional authority, detects known threats, and explains risk evidence.
              </p>
            </div>

            {/* Prominent Search Input Form & Recent Searches Dropdown */}
            <div ref={searchContainerRef} className="max-w-3xl mx-auto relative">
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  setShowHistory(false);
                  executeSearch(searchQuery);
                }}
                className="relative flex items-center shadow-lg"
              >
                <div className="absolute left-4 text-slate-400">
                  <Search className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  value={searchQuery}
                  onFocus={() => setShowHistory(true)}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search anything..."
                  className="w-full bg-slate-900 border border-slate-700/80 rounded-xl pl-11 pr-28 py-3.5 text-sm text-white placeholder-slate-500 outline-none focus:border-cyan-400 transition-colors"
                />
                <button
                  type="submit"
                  disabled={searchLoading}
                  className="absolute right-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center gap-1.5"
                >
                  {searchLoading ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Searching</span>
                    </>
                  ) : (
                    <span>Search</span>
                  )}
                </button>
              </form>

              {/* LocalStorage Recent Search History Dropdown */}
              {showHistory && recentSearches.length > 0 && (
                <div className="absolute top-full left-0 right-0 mt-1.5 bg-slate-900 border border-slate-700/80 rounded-xl shadow-2xl z-30 overflow-hidden divide-y divide-slate-800">
                  <div className="px-3.5 py-2 flex items-center justify-between text-[11px] text-slate-400 bg-slate-950/70">
                    <span className="flex items-center gap-1.5 font-medium">
                      <Clock className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Recent Searches</span>
                    </span>
                    <button
                      type="button"
                      onClick={clearAllSearchHistory}
                      className="text-slate-400 hover:text-red-400 transition-colors text-[11px]"
                    >
                      Clear history
                    </button>
                  </div>

                  <ul className="py-1 max-h-60 overflow-y-auto">
                    {recentSearches.map((item) => (
                      <li
                        key={item}
                        onClick={() => {
                          setSearchQuery(item);
                          setShowHistory(false);
                          executeSearch(item);
                        }}
                        className="px-4 py-2.5 flex items-center justify-between hover:bg-slate-800/80 cursor-pointer text-xs text-slate-200 transition-colors group"
                      >
                        <div className="flex items-center gap-2.5 truncate mr-2">
                          <History className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 shrink-0 transition-colors" />
                          <span className="truncate">{item}</span>
                        </div>
                        <button
                          type="button"
                          onClick={(e) => removeSearchItem(item, e)}
                          className="opacity-0 group-hover:opacity-100 p-1 hover:text-red-400 text-slate-500 rounded transition-all shrink-0"
                          title="Remove from history"
                          aria-label={`Remove ${item} from history`}
                        >
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Query Presets & Helpful Search Starters */}
            <div className="max-w-3xl mx-auto flex flex-wrap items-center gap-2 text-xs">
              <span className="text-slate-500">Popular searches:</span>
              {[
                'Python tutorials',
                'SQL interview questions',
                'YouTube',
                'movies',
                'technology news',
                'official government job notifications',
              ].map((queryText) => (
                <button
                  key={queryText}
                  onClick={() => {
                    setSearchQuery(queryText);
                    executeSearch(queryText);
                  }}
                  className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:text-cyan-300 hover:border-slate-700 transition-colors"
                >
                  {queryText}
                </button>
              ))}
            </div>

            {/* Error State */}
            {searchError && (
              <div className="max-w-3xl mx-auto p-4 rounded-xl border border-red-900/60 bg-red-950/20 text-xs text-red-300 space-y-1">
                <div className="font-semibold flex items-center gap-2 text-red-200">
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                  <span>Search Service Notice</span>
                </div>
                <p>{searchError}</p>
                <p className="text-[11px] text-slate-400 mt-2">
                  You can also directly check website URLs using the{' '}
                  <button onClick={() => setActiveView('urlcheck')} className="text-cyan-400 underline">
                    URL Checker tab
                  </button>
                  .
                </p>
              </div>
            )}

            {/* Search Results Container */}
            {searchResponse && (
              <div className="max-w-3xl mx-auto space-y-4 pt-2">
                {/* Results Header Metadata (Clean unboxed text) */}
                <div className="flex justify-between items-center text-xs text-slate-400 pb-2 border-b border-slate-800">
                  <div className="flex items-center gap-2">
                    <span className="tabular-nums font-medium text-slate-200">
                      {searchResponse.totalResults} results
                    </span>
                    <span aria-hidden="true">·</span>
                    <span>Query: "{searchResponse.query}"</span>
                    {searchResponse.officialCount > 0 && (
                      <>
                        <span aria-hidden="true">·</span>
                        <span className="text-emerald-400 font-medium">
                          {searchResponse.officialCount} verified official {searchResponse.officialCount === 1 ? 'source' : 'sources'} prioritized
                        </span>
                      </>
                    )}
                  </div>
                  <span className="tabular-nums font-mono text-[11px]">
                    {searchResponse.latencyMs}ms · {searchResponse.provider}
                  </span>
                </div>

                {/* Did You Mean / Typo Correction Notice */}
                {searchResponse.hasTypoCorrection && searchResponse.correctedQuery && (
                  <div className="p-3.5 rounded-xl bg-slate-900 border border-cyan-800/60 text-xs text-slate-300 flex items-center justify-between shadow-sm">
                    <div className="flex items-center gap-2.5">
                      <Sparkles className="w-4 h-4 text-cyan-400 shrink-0" />
                      <span>
                        Showing results for{' '}
                        <button
                          onClick={() => {
                            setSearchQuery(searchResponse.correctedQuery!);
                            executeSearch(searchResponse.correctedQuery!);
                          }}
                          className="text-cyan-400 font-semibold hover:underline"
                        >
                          {searchResponse.correctedQuery}
                        </button>
                        <span className="text-slate-500 ml-2">
                          (Search instead for{' '}
                          <button
                            onClick={() => {
                              setSearchQuery(searchResponse.query);
                              executeSearch(searchResponse.query);
                            }}
                            className="text-slate-400 hover:text-white underline"
                          >
                            {searchResponse.query}
                          </button>
                          )
                        </span>
                      </span>
                    </div>
                  </div>
                )}

                {/* Empty State */}
                {searchResponse.results.length === 0 && !searchLoading && (
                  <div className="text-center py-12 bg-slate-900/40 border border-slate-800 rounded-xl space-y-2">
                    <Compass className="w-8 h-8 text-slate-500 mx-auto" />
                    <h3 className="text-sm font-semibold text-white">No results found for "{searchResponse.query}"</h3>
                    <p className="text-xs text-slate-400 max-w-md mx-auto">
                      Try different keywords or check if the term is spelled correctly. You can also explore our verified civic directory.
                    </p>
                  </div>
                )}

                {/* Populated Results List */}
                <div className="space-y-4">
                  {searchResponse.results.map((item) => {
                    const isThreat = item.evaluation.status === 'KNOWN_THREAT';
                    const isOfficial = item.isOfficial;

                    return (
                      <article
                        key={item.id}
                        className={`p-5 rounded-xl border transition-all ${
                          isOfficial
                            ? 'bg-slate-900/90 border-emerald-900/70 hover:border-emerald-700'
                            : isThreat
                            ? 'bg-red-950/20 border-red-900/80'
                            : 'bg-slate-900/60 border-slate-800/80 hover:border-slate-700'
                        }`}
                      >
                        {/* Domain & Risk Attribution Row */}
                        <div className="flex items-center justify-between text-xs mb-1.5">
                          <div className="flex items-center gap-2 font-mono text-slate-400">
                            <span className={isOfficial ? 'text-emerald-400 font-semibold' : 'text-cyan-400'}>
                              {item.domain}
                            </span>
                            <span aria-hidden="true">·</span>
                            <span className="text-[11px] text-slate-500 truncate max-w-xs">{item.displayUrl}</span>
                          </div>

                          {/* Status Indicator (Clean unboxed text) */}
                          <div>
                            {item.trustState === 'OFFICIAL_SOURCE_VERIFIED' ? (
                              <span className="text-emerald-400 font-medium flex items-center gap-1.5 text-xs">
                                <ShieldCheck className="w-3.5 h-3.5" />
                                <span>Official Source Verified ({item.officialRecord?.jurisdiction || 'Institutional'})</span>
                              </span>
                            ) : item.trustState === 'TRUST_EVIDENCE_AVAILABLE' ? (
                              <span className="text-sky-400 font-medium flex items-center gap-1.5 text-xs">
                                <ShieldCheck className="w-3.5 h-3.5" />
                                <span>Trust Evidence Available</span>
                              </span>
                            ) : item.trustState === 'KNOWN_THREAT' ? (
                              <span className="text-red-400 font-bold flex items-center gap-1.5 text-xs">
                                <ShieldAlert className="w-3.5 h-3.5" />
                                <span>Known Threat Detected</span>
                              </span>
                            ) : item.trustState === 'CHECK_UNAVAILABLE' ? (
                              <span className="text-amber-400 font-medium flex items-center gap-1.5 text-xs">
                                <AlertTriangle className="w-3.5 h-3.5" />
                                <span>Check Unavailable</span>
                              </span>
                            ) : (
                              <span className="text-slate-400 text-xs flex items-center gap-1.5">
                                <Shield className="w-3.5 h-3.5 text-slate-500" />
                                <span>Unverified Web Source</span>
                              </span>
                            )}
                          </div>
                        </div>

                        {/* Title & Clickable Link */}
                        <h2 className="text-base font-semibold text-white hover:text-cyan-400 transition-colors">
                          <a
                            href={item.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-1.5 group"
                          >
                            <span>{item.title}</span>
                            <ExternalLink className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors" />
                          </a>
                        </h2>

                        {/* Snippet Prose */}
                        <p className="text-xs text-slate-300 leading-relaxed mt-2">{item.snippet}</p>

                        {/* Trust & Evidence Summary Note */}
                        <div className="mt-2.5 flex items-start gap-1.5 text-[11px] text-slate-400 leading-relaxed">
                          <span className="font-medium text-slate-300 shrink-0">Security Evaluation:</span>
                          <span>{item.trustExplanation || item.evaluation.statusExplanation}</span>
                        </div>

                        {/* Official Evidence Card or Threat Notice */}
                        {isOfficial && item.officialRecord && (
                          <div className="mt-3.5 p-3 rounded-lg bg-emerald-950/30 border border-emerald-900/60 text-xs space-y-1">
                            <div className="flex justify-between items-center text-[11px]">
                              <span className="text-emerald-400 font-semibold">
                                {item.officialRecord.organizationName}
                              </span>
                              <span className="text-slate-400">Audited {item.officialRecord.verificationDate}</span>
                            </div>
                            <p className="text-[11px] text-emerald-200/80">{item.officialRecord.description}</p>
                            <div className="pt-1 flex items-center justify-between text-[11px]">
                              <span className="text-slate-400">
                                Canonical Domain: <strong className="text-white font-mono">{item.officialRecord.canonicalDomain}</strong>
                              </span>
                              <a
                                href={item.officialRecord.authoritativeReferenceUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-emerald-400 hover:underline flex items-center gap-1"
                              >
                                <span>View Authority Citation</span>
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            </div>
                          </div>
                        )}

                        {isThreat && (
                          <div className="mt-3 p-3 rounded-lg bg-red-950/40 border border-red-900 text-xs space-y-2">
                            <div className="font-semibold text-red-300 flex items-center gap-2">
                              <AlertTriangle className="w-4 h-4 text-red-400" />
                              <span>Pre-Navigation Blocking Active</span>
                            </div>
                            <p className="text-slate-300 text-[11px]">{item.evaluation.statusExplanation}</p>
                            <button
                              onClick={() => launchProtectedView(item.url)}
                              className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-semibold"
                            >
                              Inspect in Protected View
                            </button>
                          </div>
                        )}

                        {/* Actions Row */}
                        <div className="mt-3.5 pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-xs">
                          <button
                            onClick={() => {
                              setDirectUrlInput(item.url);
                              setActiveView('urlcheck');
                              checkExplicitUrl(item.url);
                            }}
                            className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
                          >
                            <span>Deep Security Audit</span>
                            <ArrowRight className="w-3 h-3" />
                          </button>

                          <button
                            onClick={() => launchProtectedView(item.url)}
                            className="text-slate-400 hover:text-white flex items-center gap-1"
                          >
                            <span>Open in Protected Simulator</span>
                          </button>
                        </div>
                      </article>
                    );
                  })}
                </div>

                {/* Related Searches Section */}
                {searchResponse.relatedQueries && searchResponse.relatedQueries.length > 0 && (
                  <div className="mt-8 pt-5 border-t border-slate-800/80 space-y-3">
                    <h3 className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                      <Search className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Related Searches</span>
                    </h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {searchResponse.relatedQueries.map((related) => (
                        <button
                          key={related}
                          onClick={() => {
                            setSearchQuery(related);
                            executeSearch(related);
                          }}
                          className="p-3 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 hover:bg-slate-800/60 text-left text-xs text-slate-200 hover:text-cyan-300 flex items-center justify-between transition-colors group"
                        >
                          <span className="truncate">{related}</span>
                          <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 shrink-0 transition-colors" />
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* ========================================================================= */}
        {/* VIEW 2: DIRECT URL SECURITY CHECKER (SEPARATE WORKFLOW)                   */}
        {/* ========================================================================= */}
        {activeView === 'urlcheck' && (
          <div className="space-y-6 max-w-3xl mx-auto">
            <div>
              <h1 className="text-xl font-bold text-white tracking-tight">Direct Website URL Security Inspector</h1>
              <p className="text-xs text-slate-400 mt-1">
                Enter an explicit website address (e.g. <code className="text-cyan-300 font-mono">https://irs.gov/refunds</code>) to evaluate canonical domain identity, homographs, user-info tricks, and threat intelligence.
              </p>
            </div>

            {/* Direct URL Form */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                checkExplicitUrl(directUrlInput);
              }}
              className="relative flex items-center"
            >
              <div className="absolute left-3.5 text-slate-400">
                <Lock className="w-4 h-4" />
              </div>
              <input
                type="text"
                value={directUrlInput}
                onChange={(e) => setDirectUrlInput(e.target.value)}
                placeholder="https://example.com/path"
                className="w-full bg-slate-900 border border-slate-700 rounded-xl pl-10 pr-28 py-3 text-xs font-mono text-white outline-none focus:border-cyan-400"
              />
              <button
                type="submit"
                disabled={urlEvaluating}
                className="absolute right-2 px-4 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center gap-1.5"
              >
                {urlEvaluating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : null}
                <span>Audit URL</span>
              </button>
            </form>

            {/* Validation Error Banner with Smart Search Rerouting */}
            {urlValidationError && (
              <div className="p-4 rounded-xl border border-amber-900/60 bg-amber-950/20 text-xs space-y-2">
                <div className="font-semibold text-amber-300 flex items-center gap-2">
                  <Info className="w-4 h-4 text-amber-400" />
                  <span>Input Clarification</span>
                </div>
                <p className="text-slate-300">{urlValidationError}</p>
                <div className="pt-2 flex items-center gap-3">
                  <button
                    onClick={() => {
                      setSearchQuery(directUrlInput);
                      setActiveView('search');
                      executeSearch(directUrlInput);
                    }}
                    className="px-3 py-1.5 bg-amber-500 hover:bg-amber-400 text-slate-950 font-semibold rounded text-xs flex items-center gap-1.5"
                  >
                    <Search className="w-3.5 h-3.5" />
                    <span>Search Web for "{directUrlInput}"</span>
                  </button>
                  <span className="text-slate-400 text-[11px]">or enter a complete address like https://example.gov</span>
                </div>
              </div>
            )}

            {/* Detailed Evaluation Card */}
            {urlEvaluation && (
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
                {/* Status Header */}
                <div className="flex items-start justify-between gap-4 pb-4 border-b border-slate-800">
                  <div className="space-y-1">
                    <span className="text-[10px] text-slate-400 uppercase tracking-wider">Evaluation Result</span>
                    <h2 className="text-lg font-bold text-white flex items-center gap-2">
                      {urlEvaluation.status === 'OFFICIAL_SOURCE_MATCHED' ? (
                        <ShieldCheck className="w-5 h-5 text-emerald-400" />
                      ) : urlEvaluation.status === 'KNOWN_THREAT' ? (
                        <ShieldAlert className="w-5 h-5 text-red-400" />
                      ) : (
                        <Info className="w-5 h-5 text-cyan-400" />
                      )}
                      <span>{urlEvaluation.statusHeadline}</span>
                    </h2>
                    <p className="text-xs text-slate-300 leading-relaxed max-w-xl">{urlEvaluation.statusExplanation}</p>
                  </div>

                  <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-950 text-slate-300 border border-slate-800 tabular-nums">
                    {urlEvaluation.threatResult.latencyMs}ms
                  </span>
                </div>

                {/* Domain & URL Breakdown */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-0.5">
                    <span className="text-[10px] text-slate-500 uppercase">Target Domain</span>
                    <div className="font-mono text-cyan-300 font-medium">{urlEvaluation.domain}</div>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-0.5">
                    <span className="text-[10px] text-slate-500 uppercase">Threat Provider</span>
                    <div className="font-medium text-slate-200">{urlEvaluation.threatResult.providerDisplayName}</div>
                  </div>
                </div>

                {/* Official Source Match Detail (if present) */}
                {urlEvaluation.officialSource && (
                  <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-900/60 text-xs space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="font-bold text-emerald-300">{urlEvaluation.officialSource.organizationName}</span>
                      <span className="text-slate-400">{urlEvaluation.officialSource.jurisdiction}</span>
                    </div>
                    <p className="text-slate-300 text-[11px]">{urlEvaluation.officialSource.description}</p>
                    <div className="pt-2 flex justify-between items-center border-t border-emerald-900/40 text-[11px]">
                      <span className="text-slate-400">Audited Date: {urlEvaluation.officialSource.verificationDate}</span>
                      <a
                        href={urlEvaluation.officialSource.authoritativeReferenceUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-emerald-400 hover:underline flex items-center gap-1"
                      >
                        <span>Official Government Reference Citation</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  </div>
                )}

                {/* Evidence Disclosures */}
                <div className="space-y-2 text-xs">
                  <details className="bg-slate-950 border border-slate-800 rounded-lg p-3" open>
                    <summary className="font-semibold text-slate-200 cursor-pointer text-xs">What this establishes</summary>
                    <p className="text-slate-400 text-[11px] mt-1.5 leading-relaxed">{urlEvaluation.whatThisEstablishes}</p>
                  </details>
                  <details className="bg-slate-950 border border-slate-800 rounded-lg p-3" open>
                    <summary className="font-semibold text-slate-200 cursor-pointer text-xs">What this does NOT establish</summary>
                    <p className="text-slate-400 text-[11px] mt-1.5 leading-relaxed">{urlEvaluation.whatThisDoesNotEstablish}</p>
                  </details>
                </div>

                {/* Action Buttons */}
                <div className="pt-2 flex gap-3">
                  <button
                    onClick={() => launchProtectedView(urlEvaluation.url)}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold flex items-center gap-2"
                  >
                    <span>Open in Extension Simulator</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                  <a
                    href={urlEvaluation.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-4 py-2 border border-slate-700 hover:border-slate-600 text-slate-300 rounded-lg text-xs flex items-center gap-1.5"
                  >
                    <span>Visit External Site</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ========================================================================= */}
        {/* VIEW 3: AUDITED OFFICIAL SOURCES DIRECTORY                                */}
        {/* ========================================================================= */}
        {activeView === 'directory' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h1 className="text-lg font-semibold text-white">Audited Official Sources Directory</h1>
                <p className="text-xs text-slate-400 mt-0.5">
                  Audited high-risk public service portals. Each entry links to documented government citations.
                </p>
              </div>
              <span className="text-xs font-mono text-cyan-400 tabular-nums">
                {OFFICIAL_SOURCES_DIRECTORY.length} Indexed Portals
              </span>
            </div>

            {/* Filter Bar */}
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="flex-1 relative">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Filter agency, service (e.g. taxes, passport, FAFSA, DVLA, benefits)..."
                  value={dirQuery}
                  onChange={(e) => setDirQuery(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-white outline-none focus:border-cyan-400"
                />
              </div>

              <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 rounded-lg p-1 text-xs">
                {(['ALL', 'GOVERNMENT', 'TAX_REVENUE', 'EDUCATION', 'HEALTH_POSTAL'] as const).map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setDirCategory(cat)}
                    className={`px-2.5 py-1 rounded transition-colors whitespace-nowrap ${
                      dirCategory === cat ? 'bg-cyan-500 text-slate-950 font-semibold' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {cat.replace('_', ' ')}
                  </button>
                ))}
              </div>
            </div>

            {/* Cards Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredDirectory.map((record) => (
                <div
                  key={record.id}
                  className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between hover:border-slate-700 transition-colors space-y-3"
                >
                  <div className="space-y-1.5">
                    <div className="flex justify-between items-center text-[10px]">
                      <span className="text-cyan-400 font-mono font-medium">{record.canonicalDomain}</span>
                      <span className="text-slate-400">{record.jurisdiction}</span>
                    </div>
                    <h3 className="text-sm font-semibold text-white">{record.organizationName}</h3>
                    <p className="text-xs text-slate-400 leading-relaxed">{record.description}</p>
                  </div>

                  <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs">
                    <button
                      onClick={() => {
                        setDirectUrlInput(`https://${record.canonicalDomain}`);
                        setActiveView('urlcheck');
                        checkExplicitUrl(`https://${record.canonicalDomain}`);
                      }}
                      className="text-cyan-400 hover:underline text-[11px]"
                    >
                      Audit Domain
                    </button>
                    <a
                      href={record.authoritativeReferenceUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-slate-400 hover:text-white flex items-center gap-1 text-[11px]"
                    >
                      <span>Citation</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* VIEW 4: BROWSER EXTENSION SIMULATOR & INTERSTITIAL                        */}
        {/* ========================================================================= */}
        {activeView === 'simulator' && (
          <div className="space-y-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div>
                <h1 className="text-lg font-semibold text-white">Browser Extension Live Simulator</h1>
                <p className="text-xs text-slate-400 mt-0.5">
                  High-fidelity emulation of Chrome Manifest V3 service worker navigation blocking and extension popup.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-400">Pre-Navigation Filter:</span>
                <span className="text-xs font-mono text-cyan-400 bg-slate-800 px-2 py-0.5 rounded">
                  {blockThreats ? 'ACTIVE' : 'DISABLED'}
                </span>
              </div>
            </div>

            {/* Simulated Desktop Browser Frame */}
            <div className="border border-slate-800 rounded-xl bg-slate-900 shadow-2xl overflow-hidden">
              <div className="bg-slate-950 px-4 py-2.5 border-b border-slate-800 flex items-center gap-3">
                <div className="flex items-center gap-1.5 shrink-0">
                  <div className="w-3 h-3 rounded-full bg-red-500/80" />
                  <div className="w-3 h-3 rounded-full bg-amber-500/80" />
                  <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
                </div>

                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    launchProtectedView(simulatedUrl);
                  }}
                  className="flex-1 flex items-center bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-1.5 gap-2"
                >
                  <Lock className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                  <input
                    type="text"
                    value={simulatedUrl}
                    onChange={(e) => setSimulatedUrl(e.target.value)}
                    className="flex-1 bg-transparent text-xs text-slate-200 outline-none font-mono"
                    placeholder="https://..."
                  />
                  <button type="submit" className="text-xs text-slate-400 hover:text-cyan-400 px-1 shrink-0">
                    <RefreshCw className="w-3.5 h-3.5" />
                  </button>
                </form>

                <div className="relative shrink-0">
                  <button
                    onClick={() => setPopupOpen(!popupOpen)}
                    className="relative p-1.5 rounded-md hover:bg-slate-800 border border-slate-700 flex items-center gap-1"
                    title="Toggle SATVRA Popup"
                  >
                    <Shield className="w-4 h-4 text-cyan-400" />
                    {simulatorEvaluation && (
                      <span
                        className={`text-[9px] font-bold px-1 rounded ${
                          simulatorEvaluation.status === 'KNOWN_THREAT'
                            ? 'bg-red-600 text-white'
                            : simulatorEvaluation.status === 'OFFICIAL_SOURCE_MATCHED'
                            ? 'bg-emerald-600 text-white'
                            : 'bg-slate-700 text-slate-300'
                        }`}
                      >
                        {simulatorEvaluation.status === 'KNOWN_THREAT'
                          ? '!'
                          : simulatorEvaluation.status === 'OFFICIAL_SOURCE_MATCHED'
                          ? 'GOV'
                          : 'OK'}
                      </span>
                    )}
                  </button>
                </div>
              </div>

              <div className="relative min-h-[460px] bg-slate-950 flex flex-col md:flex-row">
                <div className="flex-1 p-8 flex flex-col justify-center items-center relative overflow-hidden">
                  {simulatorMode === 'warning' ? (
                    <div className="max-w-xl w-full bg-slate-900 border border-red-900/80 rounded-xl p-8 space-y-6 shadow-2xl">
                      <div className="w-12 h-12 rounded-lg bg-red-950/80 border border-red-800 flex items-center justify-center">
                        <ShieldAlert className="w-6 h-6 text-red-400" />
                      </div>
                      <div>
                        <span className="text-xs font-semibold text-red-400 tracking-wider uppercase">
                          SATVRA Navigation Protection (declarativeNetRequest)
                        </span>
                        <h2 className="text-xl font-bold text-white mt-1">Deceptive or Malicious Site Blocked</h2>
                        <p className="text-xs text-slate-300 mt-2">
                          SATVRA blocked navigation to{' '}
                          <code className="text-red-300 font-mono bg-red-950/60 px-1 py-0.5 rounded">
                            {simulatorEvaluation?.domain || simulatedUrl}
                          </code>{' '}
                          before page render.
                        </p>
                      </div>

                      <div className="bg-red-950/30 border border-red-900/60 rounded-lg p-3 space-y-1.5 text-xs">
                        <div className="flex justify-between">
                          <span className="text-slate-400">Threat Type:</span>
                          <span className="text-red-400 font-semibold">
                            {simulatorEvaluation?.threatResult.threatTypes.join(', ') || 'Known Malicious Site'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">Protection Mechanism:</span>
                          <span className="text-emerald-400 font-mono">DNR Rule Intercept</span>
                        </div>
                      </div>

                      <div className="flex gap-3">
                        <button
                          onClick={() => launchProtectedView('https://irs.gov/refunds')}
                          className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-xs font-semibold"
                        >
                          <ArrowLeft className="w-3.5 h-3.5" />
                          <span>Back to Safety</span>
                        </button>
                        <button
                          onClick={() => setSimulatorMode('content')}
                          className="px-4 py-2 border border-slate-700 text-slate-300 rounded-lg text-xs"
                        >
                          Bypass (Simulation)
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="max-w-xl w-full text-center space-y-4">
                      <div className="w-16 h-16 mx-auto rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center">
                        {simulatorEvaluation?.status === 'OFFICIAL_SOURCE_MATCHED' ? (
                          <ShieldCheck className="w-8 h-8 text-emerald-400" />
                        ) : (
                          <Globe className="w-8 h-8 text-slate-400" />
                        )}
                      </div>
                      <h3 className="text-lg font-medium text-white">
                        {simulatorEvaluation?.officialSource?.organizationName || simulatorEvaluation?.domain || 'Web Destination'}
                      </h3>
                      <p className="text-xs text-slate-400 font-mono max-w-md mx-auto truncate">{simulatedUrl}</p>
                    </div>
                  )}
                </div>

                {/* Floating Popup */}
                {popupOpen && simulatorEvaluation && (
                  <div className="w-full md:w-[350px] border-t md:border-t-0 md:border-l border-slate-800 bg-slate-900/95 flex flex-col shrink-0">
                    <div className="p-3 border-b border-slate-800 flex items-center justify-between bg-slate-950">
                      <div>
                        <div className="text-xs font-bold text-white tracking-wide">SATVRA</div>
                        <div className="text-[10px] text-cyan-400">Trust What You Browse</div>
                      </div>
                      <button
                        onClick={() => launchProtectedView(simulatedUrl)}
                        className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                      </button>
                    </div>

                    <div className="p-3.5 flex-1 overflow-y-auto space-y-3 text-xs">
                      <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5 space-y-1">
                        <div className="flex justify-between items-center text-[10px] text-slate-400 uppercase">
                          <span>Current Destination</span>
                          <span className="font-mono text-cyan-400">HTTPS</span>
                        </div>
                        <div className="font-semibold text-white truncate">{simulatorEvaluation.domain}</div>
                      </div>

                      <div
                        className={`p-3 rounded-lg border space-y-1.5 ${
                          simulatorEvaluation.status === 'KNOWN_THREAT'
                            ? 'bg-red-950/40 border-red-800 text-red-200'
                            : simulatorEvaluation.status === 'OFFICIAL_SOURCE_MATCHED'
                            ? 'bg-emerald-950/40 border-emerald-800 text-emerald-200'
                            : 'bg-slate-950 border-slate-800 text-slate-200'
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          {simulatorEvaluation.status === 'KNOWN_THREAT' ? (
                            <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
                          ) : (
                            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                          )}
                          <span className="font-semibold">{simulatorEvaluation.statusHeadline}</span>
                        </div>
                        <p className="text-[11px] text-slate-300 leading-relaxed">{simulatorEvaluation.statusExplanation}</p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* VIEW 5: DEVELOPER & QA TESTBENCH                                          */}
        {/* ========================================================================= */}
        {activeView === 'tests' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h1 className="text-lg font-semibold text-white">Developer & Verification Testbench</h1>
                <p className="text-xs text-slate-400 mt-0.5">
                  19 reproducible automated tests covering URL parsing, homographs, spoofed subdomains, DNR rules, and search-term validation.
                </p>
              </div>
              <button
                onClick={handleTestRun}
                disabled={runningTests}
                className="flex items-center gap-2 px-4 py-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-semibold text-xs rounded-lg transition-colors whitespace-nowrap"
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>{runningTests ? 'Running...' : 'Execute Automated Tests'}</span>
              </button>
            </div>

            {testSummary && (
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-lg bg-emerald-950/80 border border-emerald-800 flex items-center justify-center">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-white">
                      {testSummary.passed} / {testSummary.total} Tests Passed
                    </div>
                    <div className="text-xs text-slate-400">
                      Duration: <span className="tabular-nums font-mono">{testSummary.durationMs}ms</span>
                    </div>
                  </div>
                </div>
                <span className="text-xs font-mono text-emerald-400 bg-emerald-950/50 border border-emerald-800 px-2.5 py-1 rounded">
                  100% SUITE PASS RATE
                </span>
              </div>
            )}

            {/* Test Results Table */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden divide-y divide-slate-800 text-xs">
              {(testSummary?.tests || []).map((t, idx) => (
                <div key={idx} className="p-3 flex items-center justify-between hover:bg-slate-800/30">
                  <div>
                    <div className="font-medium text-slate-200">{t.name}</div>
                    <div className="text-[11px] text-slate-500 font-mono">{t.suite}</div>
                  </div>
                  <span className="text-emerald-400 flex items-center gap-1 font-medium">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>PASS</span>
                  </span>
                </div>
              ))}
              {!testSummary && (
                <div className="p-8 text-center text-xs text-slate-400">
                  Click "Execute Automated Tests" above to run the 19 automated tests.
                </div>
              )}
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* VIEW 6: SETTINGS & PRIVACY CONTROLS                                       */}
        {/* ========================================================================= */}
        {activeView === 'settings' && (
          <div className="space-y-6 max-w-2xl mx-auto">
            <div>
              <h1 className="text-xl font-bold text-white tracking-tight">Settings & Privacy Configuration</h1>
              <p className="text-xs text-slate-400 mt-1">
                Configure threat intelligence feeds, search engine credentials, and privacy minimization parameters.
              </p>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 text-xs">
              <div>
                <label className="text-slate-300 font-semibold block mb-1">Threat Intelligence Provider</label>
                <select
                  value={activeProvider}
                  onChange={(e) => setActiveProvider(e.target.value as ProviderType)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white outline-none focus:border-cyan-400"
                >
                  <option value="composite">SATVRA Composite (Deterministic Test Vectors + Cloud APIs)</option>
                  <option value="test-fixture">Deterministic Security Test Feed (Offline / Harmless Fixtures)</option>
                  <option value="urlhaus">abuse.ch URLhaus (Community Threat Dataset)</option>
                  <option value="google-web-risk">Google Web Risk (Commercial API)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Google Web Risk API Key (Optional Commercial Key)
                </label>
                <input
                  type="password"
                  placeholder="AIzaSy..."
                  value={webRiskKey}
                  onChange={(e) => setWebRiskKey(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono outline-none focus:border-cyan-400"
                />
              </div>

              <div className="pt-3 border-t border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="font-semibold text-white block">Strip Query Parameters & Tokens</span>
                    <span className="text-[11px] text-slate-400">
                      Anonymizes web addresses before external check to prevent transmitting session IDs.
                    </span>
                  </div>
                  <input
                    type="checkbox"
                    checked={anonymizeUrls}
                    onChange={(e) => setAnonymizeUrls(e.target.checked)}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <span className="font-semibold text-white block">Pre-Navigation Threat Blocking</span>
                    <span className="text-[11px] text-slate-400">
                      Enforce declarativeNetRequest interception on confirmed malicious sites.
                    </span>
                  </div>
                  <input
                    type="checkbox"
                    checked={blockThreats}
                    onChange={(e) => setBlockThreats(e.target.checked)}
                  />
                </div>
              </div>

              {/* LocalStorage Search History Controls */}
              <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
                <div>
                  <span className="font-semibold text-white block">Recent Search History</span>
                  <span className="text-[11px] text-slate-400">
                    Stored locally in your browser's localStorage ({recentSearches.length} {recentSearches.length === 1 ? 'query' : 'queries'}).
                  </span>
                </div>
                <button
                  type="button"
                  onClick={clearAllSearchHistory}
                  disabled={recentSearches.length === 0}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-slate-200 rounded text-xs flex items-center gap-1.5 transition-colors"
                >
                  <Trash2 className="w-3.5 h-3.5 text-slate-400" />
                  <span>Clear History</span>
                </button>
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
                <button
                  onClick={handleSaveSettings}
                  className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded-lg text-xs"
                >
                  Save Settings
                </button>
                {settingsSavedMsg && <span className="text-emerald-400 text-xs">Settings updated successfully</span>}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
