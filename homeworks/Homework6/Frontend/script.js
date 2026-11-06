const form = document.getElementById('threatForm');
const relationshipSelect = document.getElementById('relationship');
const sourceSelect = document.getElementById('source');
const promptInput = document.getElementById('prompt');
const attachmentInput = document.getElementById('attachment');
const statusMessage = document.getElementById('statusMessage');
const resultSection = document.getElementById('resultSection');
const scoreValue = document.getElementById('scoreValue');
const riskLabel = document.getElementById('riskLabel');
const meterFill = document.getElementById('meterFill');
const assessmentText = document.getElementById('assessmentText');

const MAX_MESSAGE_CHARS = 2000;
const VALID_EXTENSIONS = ['.txt', '.eml'];
const DANGEROUS_PATTERNS = [
  { pattern: /\b(urgent|immediately|now|today|asap|act now)\b/i, weight: 14 },
  { pattern: /\b(click|open|follow|tap|visit)\b.*\b(link|site|portal|page|attachment)\b/i, weight: 16 },
  { pattern: /\b(password|credentials|account|reset|verify)\b/i, weight: 18 },
  { pattern: /\b(wire transfer|bank account|gift card|crypto|bitcoin|paypal)\b/i, weight: 18 },
  { pattern: /\b(secret|confidential|private|sensitive)\b/i, weight: 10 },
  { pattern: /\b(please do not tell|keep this confidential|between us)\b/i, weight: 12 },
  { pattern: /\b(free money|limited time|offer expires|final notice)\b/i, weight: 15 }
];

function sanitizeText(value) {
  if (value === null || value === undefined) {
    return '';
  }

  const text = String(value)
    .replace(/[\u0000-\u001F\u007F]/g, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  return text.slice(0, MAX_MESSAGE_CHARS);
}

function isAllowedFile(file) {
  if (!file) {
    return true;
  }

  const fileName = file.name || '';
  const extension = fileName.slice(fileName.lastIndexOf('.')).toLowerCase();
  const mimeType = (file.type || '').toLowerCase();

  return VALID_EXTENSIONS.includes(extension) || mimeType === 'text/plain' || mimeType === 'message/rfc822';
}

function getRiskInfo(score) {
  if (score >= 61) {
    return {
      label: 'Malicious intent',
      color: '#d93d3d',
      message: 'High likelihood of a malicious or manipulative social engineering attempt.'
    };
  }

  if (score >= 31) {
    return {
      label: 'Likely malicious',
      color: '#f39c12',
      message: 'This message shows multiple suspicious indicators and should be treated as likely malicious.'
    };
  }

  if (score >= 1) {
    return {
      label: 'Cautious',
      color: '#f1c40f',
      message: 'This message is not clearly malicious, but caution is advised because it contains concerning patterns.'
    };
  }

  return {
    label: 'Harmless',
    color: '#2ecc71',
    message: 'The content appears benign based on the information provided and does not indicate a strong threat.'
  };
}

function updateGauge(score) {
  const normalizedScore = Math.min(100, Math.max(0, Number(score) || 0));
  const risk = getRiskInfo(normalizedScore);

  scoreValue.textContent = `${normalizedScore}`;
  riskLabel.textContent = risk.label;
  meterFill.style.width = `${normalizedScore}%`;
  meterFill.style.background = `linear-gradient(90deg, ${risk.color} 0%, ${risk.color} 100%)`;

  if (normalizedScore >= 61) {
    riskLabel.style.color = '#d93d3d';
  } else if (normalizedScore >= 31) {
    riskLabel.style.color = '#f39c12';
  } else if (normalizedScore >= 1) {
    riskLabel.style.color = '#f1c40f';
  } else {
    riskLabel.style.color = '#2ecc71';
  }

  assessmentText.textContent = risk.message;
}

function computeFallbackScore(message, relation, source) {
  let score = 0;

  for (const item of DANGEROUS_PATTERNS) {
    if (item.pattern.test(message)) {
      score += item.weight;
    }
  }

  if (/\b(verify|update|confirm|secure|urgent)/i.test(message)) {
    score += 8;
  }

  if (/\b(attachment|download|link|click|credential|password)\b/i.test(message)) {
    score += 10;
  }

  if (source === 'Email') {
    score += 5;
  }

  if (relation === 'Employee' || relation === 'Friend/Family') {
    score += 8;
  }

  if (relation === 'No Personal Relation') {
    score += 6;
  }

  return Math.min(100, Math.max(0, score));
}

function buildFallbackAssessment(score, message) {
  const risk = getRiskInfo(score);
  const evidence = [];

  for (const item of DANGEROUS_PATTERNS) {
    if (item.pattern.test(message)) {
      evidence.push(item.pattern.source);
    }
  }

  const evidenceText = evidence.length
    ? `Detected patterns: ${evidence.slice(0, 3).join(', ')}.`
    : 'No strongly suspicious language patterns were detected in the provided text.';

  return `${risk.message} ${evidenceText}`;
}

async function readAttachedFile(file) {
  if (!file) {
    return '';
  }

  if (!isAllowedFile(file)) {
    throw new Error('Only .txt and .eml files are supported.');
  }

  const text = await file.text();
  return sanitizeText(text);
}

async function analyzeThreatIntent(payload) {
  const response = await fetch('/api/social-engineering-analysis', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'social-engineering-frontend'
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error(`Backend returned ${response.status}`);
  }

  return response.json();
}

function setStatus(message, isError = false) {
  statusMessage.textContent = message;
  statusMessage.classList.toggle('error', isError);
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();

  const relationship = sanitizeText(relationshipSelect.value);
  const source = sanitizeText(sourceSelect.value);
  const messageText = sanitizeText(promptInput.value);

  if (!relationship || !source || !messageText) {
    setStatus('Please complete the relationship, source, and message fields before submitting.', true);
    return;
  }

  const file = attachmentInput.files && attachmentInput.files[0] ? attachmentInput.files[0] : null;

  if (file && !isAllowedFile(file)) {
    setStatus('Only .txt and .eml files can be uploaded.', true);
    return;
  }

  const requestPayload = {
    relationship,
    source,
    message: messageText,
    fileName: file ? file.name : null
  };

  try {
    setStatus('Analyzing the message for social engineering indicators...');

    const fileContent = await readAttachedFile(file);
    const fullMessage = sanitizeText(`${messageText}\n${fileContent}`);

    const backendPayload = {
      ...requestPayload,
      message: fullMessage,
      fileContent
    };

    const result = await analyzeThreatIntent(backendPayload);
    const score = Number(result.score ?? result.malicious_intent ?? 0);

    updateGauge(Number.isFinite(score) ? score : 0);
    resultSection.classList.remove('hidden');
    assessmentText.textContent = result.assessment || result.analysis || getRiskInfo(score).message;
    setStatus('Analysis complete.');
  } catch (error) {
    const fullMessage = sanitizeText(`${messageText} ${attachmentInput.files && attachmentInput.files[0] ? await readAttachedFile(file).catch(() => '') : ''}`);
    const fallbackScore = computeFallbackScore(fullMessage, relationship, source);
    updateGauge(fallbackScore);
    resultSection.classList.remove('hidden');
    assessmentText.textContent = buildFallbackAssessment(fallbackScore, fullMessage);
    setStatus('Backend unavailable. Local threat analysis used as a fallback.', false);
  }
});

document.getElementById('resetBtn').addEventListener('click', () => {
  form.reset();
  resultSection.classList.add('hidden');
  assessmentText.textContent = 'No assessment available yet.';
  scoreValue.textContent = '0';
  riskLabel.textContent = 'Harmless';
  meterFill.style.width = '0%';
  setStatus('');
});

updateGauge(0);
resultSection.classList.add('hidden');
