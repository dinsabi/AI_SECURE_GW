import express from 'express';
const app = express();
app.use(express.json());

app.post('/score', (req, res) => {
  const { user, inspection } = req.body;
  let score = 0;
  if (inspection.classification === 'critical') score += 70;
  else if (inspection.classification === 'confidential') score += 35;
  if ((inspection.categories || []).includes('secret')) score += 25;
  if ((user.department || '') === 'Finance' || (user.department || '') === 'HR') score += 10;
  if ((user.country || 'BE') !== 'BE') score += 10;
  if (!user.mfaVerified) score += 30;
  const level = score >= 70 ? 'HIGH' : score >= 35 ? 'MEDIUM' : 'LOW';
  res.json({ score, level });
});
app.listen(process.env.PORT || 3002, () => console.log('risk-engine ready'));
