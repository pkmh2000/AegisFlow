// Browser Web Audio API Security Alert Synthesizer (works 100% offline with zero external audio files)

let sharedAudioCtx: AudioContext | null = null;

function getAudioContext(): AudioContext | null {
  if (typeof window === 'undefined') return null;
  const AudioCtx =
    window.AudioContext ||
    (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!AudioCtx) return null;
  if (!sharedAudioCtx || sharedAudioCtx.state === 'closed') {
    sharedAudioCtx = new AudioCtx();
  }
  return sharedAudioCtx;
}

export async function playCriticalAlertSound(): Promise<boolean> {
  const ctx = getAudioContext();
  if (!ctx) return false;

  try {
    if (ctx.state === 'suspended') {
      await ctx.resume();
    }

    const now = ctx.currentTime;
    // Two-stage high-urgency dual-pulse security alarm (880Hz -> 1174.66Hz x2)
    const sequence = [
      { start: 0.0, dur: 0.16, freq: 880 },
      { start: 0.18, dur: 0.2, freq: 1174.66 },
      { start: 0.44, dur: 0.16, freq: 880 },
      { start: 0.62, dur: 0.24, freq: 1174.66 },
    ];

    for (const note of sequence) {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = 'triangle';
      osc.frequency.setValueAtTime(note.freq, now + note.start);

      gain.gain.setValueAtTime(0.0001, now + note.start);
      gain.gain.exponentialRampToValueAtTime(0.22, now + note.start + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, now + note.start + note.dur);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start(now + note.start);
      osc.stop(now + note.start + note.dur + 0.02);
    }

    return true;
  } catch {
    return false;
  }
}
