/**
 * Incident Routes
 *
 * GET    /api/incidents           — paginated list with filters
 * POST   /api/incidents           — manually create an incident
 * GET    /api/incidents/:id       — single incident with threats populated
 * PATCH  /api/incidents/:id/status — update incident status
 * PATCH  /api/incidents/:id/notes  — update analyst notes
 *
 * All routes require a valid analyst JWT.
 */
import { Router } from 'express';
import { protect } from '../middleware/auth.js';
import {
  listIncidents,
  getIncident,
  createIncident,
  updateIncidentStatus,
  updateIncidentNotes,
  deleteIncident,
} from '../controllers/incidentController.js';

const router = Router();

router.use(protect);

router.get('/',                  listIncidents);
router.post('/',                 createIncident);
router.get('/:id',               getIncident);
router.patch('/:id/status',      updateIncidentStatus);
router.patch('/:id/notes',       updateIncidentNotes);
router.delete('/:id',            deleteIncident);

export default router;
