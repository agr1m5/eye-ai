/**
 * HolographicGlobe3D.jsx — Advanced 3D Cyber Battle Globe & Digital Twin
 *
 * Capabilities:
 *  - Procedural dot-matrix continental landmasses (North America, Europe, Asia, Africa, etc.)
 *  - Atmospheric bloom shader halo & multi-layer orbital telemetry rings
 *  - 3D Vertical Threat Energy Pillars extending into orbital space
 *  - Dynamic quadratic ballistic trajectory missile curves with trailing particles
 *  - Starfield deep space backdrop
 *  - Interactive raycasting: hover tooltip + click-to-focus camera orbit
 *  - Tactical Flight Telemetry HUD with DEFCON status and top attack corridors
 *  - In-line SOAR countermeasure trigger
 */
import { useEffect, useRef, useState, useMemo } from 'react';
import * as THREE from 'three';
import {
  Crosshair,
  Radio,
  RotateCcw,
  Zap,
  Shield,
  Activity,
  Maximize2,
  Navigation,
  Compass,
  Flame,
  Volume2,
  CheckCircle2,
  X,
} from 'lucide-react';
import { getHumanThreat } from '@/utils/threatFormatter';
import { tacticalAudio } from '@/utils/tacticalAudio';
import { defenseApi } from '@/services/api';
import toast from 'react-hot-toast';

const GLOBE_RADIUS = 125;
const SOC_COORDS = { lat: 28.6139, lon: 77.2090, label: 'RAKSHAK SOC PRIME (HQ)' };

// Convert Lat/Lon to 3D spherical coordinates (Vector3)
function latLonToVector3(lat, lon, radius = GLOBE_RADIUS) {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  const x = -(radius * Math.sin(phi) * Math.cos(theta));
  const z = radius * Math.sin(phi) * Math.sin(theta);
  const y = radius * Math.cos(phi);
  return new THREE.Vector3(x, y, z);
}

// Great-circle distance in kilometers (Haversine formula)
function calculateDistanceKm(lat1, lon1, lat2, lon2) {
  const R = 6371; // Earth radius in km
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return Math.round(R * c);
}

// Check if a coordinate falls within continental landmasses
function isLandCoordinate(lat, lon) {
  // North America
  if (lat >= 15 && lat <= 72 && lon >= -168 && lon <= -52) {
    if (lat < 30 && lon < -106) return false;
    return true;
  }
  // South America
  if (lat >= -55 && lat <= 12 && lon >= -82 && lon <= -34) {
    if (lat < -20 && lon > -40) return false;
    return true;
  }
  // Europe & UK
  if (lat >= 36 && lat <= 71 && lon >= -11 && lon <= 45) return true;
  // Africa
  if (lat >= -35 && lat <= 37 && lon >= -18 && lon <= 52) {
    if (lat < -10 && lon > 40) return false;
    return true;
  }
  // Asia & Middle East
  if (lat >= 8 && lat <= 75 && lon >= 45 && lon <= 180) {
    if (lat < 20 && lon < 65) return false;
    if (lat < 5 && lon > 65 && lon < 95) return false;
    return true;
  }
  // Australia & New Zealand
  if (lat >= -47 && lat <= -10 && lon >= 112 && lon <= 178) return true;
  // Japan
  if (lat >= 30 && lat <= 46 && lon >= 128 && lon <= 146) return true;

  return false;
}

// Generate 3D ballistic arc curve between origin and SOC base
function create3DArc(startVec, endVec, maxAltitude = 42) {
  const midPoint = new THREE.Vector3().addVectors(startVec, endVec).multiplyScalar(0.5);
  const distance = startVec.distanceTo(endVec);
  const altitude = Math.min(70, maxAltitude + distance * 0.18);
  midPoint.setLength(GLOBE_RADIUS + altitude);

  const curve = new THREE.QuadraticBezierCurve3(startVec, midPoint, endVec);
  const points = curve.getPoints(50);
  const geometry = new THREE.BufferGeometry().setFromPoints(points);
  return { geometry, curve };
}

const SEVERITY_CONFIG = {
  critical: { hex: 0xef4444, colorStr: '#ef4444', beamHeight: 28, label: 'CRITICAL' },
  high:     { hex: 0xf97316, colorStr: '#f97316', beamHeight: 20, label: 'HIGH'     },
  medium:   { hex: 0xeab308, colorStr: '#eab308', beamHeight: 14, label: 'MEDIUM'   },
  low:      { hex: 0x06b6d4, colorStr: '#06b6d4', beamHeight: 10, label: 'LOW'      },
  info:     { hex: 0x3b82f6, colorStr: '#3b82f6', beamHeight: 8,  label: 'INFO'     },
};

export default function HolographicGlobe3D({ points = [], onHoverPoint }) {
  const containerRef = useRef(null);
  const globeGroupRef = useRef(null);
  const [hoveredData, setHoveredData] = useState(null);
  const [selectedDossier, setSelectedDossier] = useState(null);
  const [autoRotate, setAutoRotate] = useState(true);
  const [speedMultiplier, setSpeedMultiplier] = useState(1);
  const [isContaining, setIsContaining] = useState(false);
  const [activeFilter, setActiveFilter] = useState('all');

  // Filtered points by severity
  const visiblePoints = useMemo(() => {
    if (activeFilter === 'all') return points;
    return points.filter((p) => p.severity === activeFilter);
  }, [points, activeFilter]);

  // Statistics
  const stats = useMemo(() => {
    const criticalCount = points.filter((p) => p.severity === 'critical').length;
    const highCount = points.filter((p) => p.severity === 'high').length;
    const defcon = criticalCount > 2 ? 1 : criticalCount > 0 ? 2 : highCount > 0 ? 3 : 4;
    return {
      total: points.length,
      critical: criticalCount,
      high: highCount,
      defcon,
    };
  }, [points]);

  // Top corridors breakdown
  const topCorridors = useMemo(() => {
    const map = {};
    points.forEach((p) => {
      const key = `${p.city ? `${p.city}, ` : ''}${p.country || 'Unknown'}`;
      map[key] = (map[key] || 0) + 1;
    });
    return Object.entries(map)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  }, [points]);

  // Trigger manual countermeasure containment from globe
  const handleContainTarget = async (target) => {
    if (!target) return;

    // Check if target is SOC HQ itself
    if (
      target.label === SOC_COORDS.label ||
      (target.lat === SOC_COORDS.lat && target.lon === SOC_COORDS.lon)
    ) {
      toast.error('Cannot contain Rakshak SOC Prime Base. HQ is protected.', { icon: '🛡️' });
      return;
    }

    const actionType = target.pid ? 'kill_process' : 'block_ip';
    let targetVal = target.pid ? String(target.pid) : target.ip;

    if (!targetVal || targetVal === 'Attacker Node' || targetVal === 'undefined') {
      toast.error('No specific IP or PID found on this threat vector to block.', { icon: '⚠️' });
      return;
    }

    try {
      setIsContaining(true);
      await defenseApi.contain({
        actionType,
        target: targetVal,
        threatId: target.id || target._id,
        reason: `3D Globe Interceptor countermeasure against ${target.country || 'Target'} (${target.type})`,
      });

      tacticalAudio.playNeutralized();
      toast.success(`⚡ Countermeasure Dispatched: ${actionType.toUpperCase()} (${targetVal})`, {
        duration: 4500,
      });
      setSelectedDossier(null);
    } catch (err) {
      const msg = err.response?.data?.message || err.message;
      toast.error(`Countermeasure failed: ${msg}`);
    } finally {
      setIsContaining(false);
    }
  };

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const width = container.clientWidth || 920;
    const height = 480;

    // 1. Scene & Camera
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 1, 3000);
    camera.position.set(0, 50, 390);

    // 2. WebGL Renderer
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.innerHTML = '';
    container.appendChild(renderer.domElement);

    // 3. Starfield Backdrop (400 deep space particles)
    const starGeo = new THREE.BufferGeometry();
    const starCount = 400;
    const starPos = new Float32Array(starCount * 3);
    for (let i = 0; i < starCount * 3; i += 3) {
      starPos[i] = (Math.random() - 0.5) * 1400;
      starPos[i + 1] = (Math.random() - 0.5) * 1400;
      starPos[i + 2] = (Math.random() - 0.5) * 1400;
    }
    starGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
    const starMat = new THREE.PointsMaterial({
      color: 0x475569,
      size: 1.5,
      transparent: true,
      opacity: 0.5,
    });
    const starField = new THREE.Points(starGeo, starMat);
    scene.add(starField);

    // 4. Globe Group (rotates on Y axis)
    const globeGroup = new THREE.Group();
    globeGroupRef.current = globeGroup;
    scene.add(globeGroup);

    // Initial rotation facing Europe / Asia
    globeGroup.rotation.y = -Math.PI * 0.65;

    // 5. Dark Base Core Sphere
    const sphereGeo = new THREE.SphereGeometry(GLOBE_RADIUS, 64, 64);
    const sphereMat = new THREE.MeshBasicMaterial({
      color: 0x040914,
    });
    const baseSphere = new THREE.Mesh(sphereGeo, sphereMat);
    globeGroup.add(baseSphere);

    // 6. Tactical Cyber Wireframe Grid
    const wireMat = new THREE.MeshBasicMaterial({
      color: 0x0e2847,
      wireframe: true,
      transparent: true,
      opacity: 0.22,
    });
    const wireSphere = new THREE.Mesh(sphereGeo, wireMat);
    globeGroup.add(wireSphere);

    // 7. Procedural Continental Dot Matrix Landmasses (~2200 points)
    const landCoords = [];
    for (let lat = -80; lat <= 80; lat += 3.5) {
      const radiusAtLat = GLOBE_RADIUS * Math.cos((lat * Math.PI) / 180);
      const stepLon = Math.max(3.5, 360 / Math.max(1, Math.floor((2 * Math.PI * radiusAtLat) / 7.5)));
      for (let lon = -180; lon <= 180; lon += stepLon) {
        if (isLandCoordinate(lat, lon)) {
          const v = latLonToVector3(lat, lon, GLOBE_RADIUS + 0.6);
          landCoords.push(v.x, v.y, v.z);
        }
      }
    }
    const landGeo = new THREE.BufferGeometry();
    landGeo.setAttribute('position', new THREE.Float32BufferAttribute(landCoords, 3));
    const landMat = new THREE.PointsMaterial({
      color: 0x00f0ff,
      size: 1.4,
      transparent: true,
      opacity: 0.42,
    });
    const landPointsMesh = new THREE.Points(landGeo, landMat);
    globeGroup.add(landPointsMesh);

    // 8. Atmospheric Glow Shader (Fresnel Bloom Halo)
    const glowGeo = new THREE.SphereGeometry(GLOBE_RADIUS * 1.16, 32, 32);
    const glowMat = new THREE.ShaderMaterial({
      vertexShader: `
        varying vec3 vNormal;
        void main() {
          vNormal = normalize(normalMatrix * normal);
          gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
        }
      `,
      fragmentShader: `
        varying vec3 vNormal;
        void main() {
          float intensity = pow(0.66 - dot(vNormal, vec3(0, 0, 1.0)), 2.6);
          gl_FragColor = vec4(0.0, 0.94, 1.0, 1.0) * intensity * 0.65;
        }
      `,
      side: THREE.BackSide,
      blending: THREE.AdditiveBlending,
      transparent: true,
    });
    const glowMesh = new THREE.Mesh(glowGeo, glowMat);
    scene.add(glowMesh);

    // 9. Dual Orbital Rings with Cyber Tick Marks
    const ring1Geo = new THREE.RingGeometry(GLOBE_RADIUS * 1.35, GLOBE_RADIUS * 1.365, 64);
    const ring1Mat = new THREE.MeshBasicMaterial({
      color: 0x00f0ff,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.22,
    });
    const ring1 = new THREE.Mesh(ring1Geo, ring1Mat);
    ring1.rotation.x = Math.PI / 2.3;
    scene.add(ring1);

    const ring2Geo = new THREE.RingGeometry(GLOBE_RADIUS * 1.5, GLOBE_RADIUS * 1.515, 64);
    const ring2Mat = new THREE.MeshBasicMaterial({
      color: 0x38bdf8,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.12,
    });
    const ring2 = new THREE.Mesh(ring2Geo, ring2Mat);
    ring2.rotation.x = -Math.PI / 3.2;
    ring2.rotation.y = Math.PI / 4;
    scene.add(ring2);

    // 10. Central SOC Defense Base HQ (New Delhi)
    const socPos = latLonToVector3(SOC_COORDS.lat, SOC_COORDS.lon, GLOBE_RADIUS + 1.5);

    // Central beacon node
    const socGeo = new THREE.SphereGeometry(4.2, 16, 16);
    const socMat = new THREE.MeshBasicMaterial({ color: 0x00f0ff });
    const socMesh = new THREE.Mesh(socGeo, socMat);
    socMesh.position.copy(socPos);
    globeGroup.add(socMesh);

    // Expanding defense pulse ring
    const socRingGeo = new THREE.RingGeometry(4.5, 8, 32);
    const socRingMat = new THREE.MeshBasicMaterial({
      color: 0x00f0ff,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.8,
    });
    const socRing = new THREE.Mesh(socRingGeo, socRingMat);
    socRing.position.copy(socPos);
    socRing.lookAt(new THREE.Vector3(0, 0, 0));
    globeGroup.add(socRing);

    // Vertical defense beacon beam to space
    const socBeamGeo = new THREE.CylinderGeometry(0.5, 1.2, 38, 12);
    const socBeamMat = new THREE.MeshBasicMaterial({
      color: 0x00f0ff,
      transparent: true,
      opacity: 0.45,
    });
    const socBeam = new THREE.Mesh(socBeamGeo, socBeamMat);
    const socNormal = socPos.clone().normalize();
    socBeam.position.copy(socPos.clone().add(socNormal.clone().multiplyScalar(19)));
    socBeam.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), socNormal);
    globeGroup.add(socBeam);

    // 11. Threat Pins, Vertical Energy Pillars & Ballistic Arcs
    const pointMeshes = [];
    const arcObjects = [];

    visiblePoints.forEach((pt) => {
      const pinPos = latLonToVector3(pt.lat, pt.lon, GLOBE_RADIUS + 1.2);
      const conf = SEVERITY_CONFIG[pt.severity] || SEVERITY_CONFIG.medium;
      const normal = pinPos.clone().normalize();

      // Pin core sphere
      const pinGeo = new THREE.SphereGeometry(pt.severity === 'critical' ? 2.8 : 2.0, 12, 12);
      const pinMat = new THREE.MeshBasicMaterial({ color: conf.hex });
      const pinMesh = new THREE.Mesh(pinGeo, pinMat);
      pinMesh.position.copy(pinPos);
      pinMesh.userData = pt;
      globeGroup.add(pinMesh);
      pointMeshes.push(pinMesh);

      // Vertical threat energy beam
      const beamHeight = conf.beamHeight;
      const beamGeo = new THREE.CylinderGeometry(0.3, 1.0, beamHeight, 8);
      const beamMat = new THREE.MeshBasicMaterial({
        color: conf.hex,
        transparent: true,
        opacity: 0.5,
      });
      const beamMesh = new THREE.Mesh(beamGeo, beamMat);
      beamMesh.position.copy(pinPos.clone().add(normal.clone().multiplyScalar(beamHeight / 2)));
      beamMesh.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), normal);
      beamMesh.userData = pt;
      globeGroup.add(beamMesh);
      pointMeshes.push(beamMesh);

      // Threat ground pulse ring
      const threatRingGeo = new THREE.RingGeometry(2.5, 4.5, 16);
      const threatRingMat = new THREE.MeshBasicMaterial({
        color: conf.hex,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.6,
      });
      const threatRing = new THREE.Mesh(threatRingGeo, threatRingMat);
      threatRing.position.copy(pinPos);
      threatRing.lookAt(new THREE.Vector3(0, 0, 0));
      globeGroup.add(threatRing);

      // Curved ballistic trajectory line
      const { geometry, curve } = create3DArc(pinPos, socPos);
      const arcMat = new THREE.LineBasicMaterial({
        color: conf.hex,
        transparent: true,
        opacity: 0.38,
        linewidth: 1,
      });
      const arcLine = new THREE.Line(geometry, arcMat);
      globeGroup.add(arcLine);

      // Traveling projectile missile particle
      const projectileGeo = new THREE.SphereGeometry(1.4, 8, 8);
      const projectileMat = new THREE.MeshBasicMaterial({ color: 0xffffff });
      const projectileMesh = new THREE.Mesh(projectileGeo, projectileMat);
      globeGroup.add(projectileMesh);

      // Trailing tail particles (3 mini particles behind main projectile)
      const tailParticles = [0.03, 0.06, 0.09].map((offset) => {
        const tailGeo = new THREE.SphereGeometry(0.8, 6, 6);
        const tailMat = new THREE.MeshBasicMaterial({
          color: conf.hex,
          transparent: true,
          opacity: 0.5,
        });
        const tailMesh = new THREE.Mesh(tailGeo, tailMat);
        globeGroup.add(tailMesh);
        return { mesh: tailMesh, offset };
      });

      arcObjects.push({
        curve,
        projectileMesh,
        tailParticles,
        speed: (0.0035 + (Math.abs(pt.lat) % 6) * 0.0006) * speedMultiplier,
        progress: Math.random(),
      });
    });

    // 12. Mouse Drag & Click Interaction
    let isDragging = false;
    let dragDistance = 0;
    let previousMousePosition = { x: 0, y: 0 };

    const onMouseDown = (e) => {
      isDragging = true;
      dragDistance = 0;
      previousMousePosition = { x: e.clientX, y: e.clientY };
    };

    const onMouseMove = (e) => {
      const rect = container.getBoundingClientRect();
      const mouseX = ((e.clientX - rect.left) / width) * 2 - 1;
      const mouseY = -((e.clientY - rect.top) / height) * 2 + 1;

      // Raycast for hover
      const raycaster = new THREE.Raycaster();
      raycaster.setFromCamera(new THREE.Vector2(mouseX, mouseY), camera);
      const intersects = raycaster.intersectObjects(pointMeshes);

      if (intersects.length > 0) {
        const target = intersects[0].object.userData;
        setHoveredData({
          ...target,
          screenX: e.clientX - rect.left,
          screenY: e.clientY - rect.top,
        });
        if (onHoverPoint) onHoverPoint(target);
      } else {
        setHoveredData(null);
        if (onHoverPoint) onHoverPoint(null);
      }

      if (!isDragging) return;

      const deltaX = e.clientX - previousMousePosition.x;
      const deltaY = e.clientY - previousMousePosition.y;
      dragDistance += Math.abs(deltaX) + Math.abs(deltaY);

      globeGroup.rotation.y += deltaX * 0.005;
      globeGroup.rotation.x = Math.max(-1.1, Math.min(1.1, globeGroup.rotation.x + deltaY * 0.005));

      previousMousePosition = { x: e.clientX, y: e.clientY };
    };

    const onMouseUp = (e) => {
      isDragging = false;
      // If click was without significant drag, treat as pin selection click
      if (dragDistance < 6) {
        const rect = container.getBoundingClientRect();
        const mouseX = ((e.clientX - rect.left) / width) * 2 - 1;
        const mouseY = -((e.clientY - rect.top) / height) * 2 + 1;
        const raycaster = new THREE.Raycaster();
        raycaster.setFromCamera(new THREE.Vector2(mouseX, mouseY), camera);
        const intersects = raycaster.intersectObjects(pointMeshes);

        if (intersects.length > 0) {
          const target = intersects[0].object.userData;
          setSelectedDossier(target);
          tacticalAudio.playRadarPing();
        }
      }
    };

    const onWheel = (e) => {
      e.preventDefault();
      camera.position.z = Math.max(210, Math.min(560, camera.position.z + e.deltaY * 0.3));
    };

    container.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);
    container.addEventListener('wheel', onWheel, { passive: false });

    // 13. Render Loop
    let animationFrameId;
    let startTime = performance.now();
    let lastTime = startTime;

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      const now = performance.now();
      const delta = (now - lastTime) / 1000;
      const elapsedTime = (now - startTime) / 1000;
      lastTime = now;

      // Continuous auto-rotation when enabled
      if (autoRotate && !isDragging) {
        globeGroup.rotation.y += 0.0018 * speedMultiplier;
      }

      // Pulse SOC defense base ring
      const socScale = 1 + Math.sin(elapsedTime * 3.5) * 0.28;
      socRing.scale.set(socScale, socScale, socScale);

      // Rotate orbital rings slowly in opposite directions
      ring1.rotation.z += 0.001;
      ring2.rotation.z -= 0.0008;

      // Animate ballistic missiles & projectile tails along trajectories
      arcObjects.forEach((arc) => {
        arc.progress = (arc.progress + arc.speed) % 1;
        const mainPos = arc.curve.getPointAt(arc.progress);
        arc.projectileMesh.position.copy(mainPos);

        // Update tail particles with trailing progress
        arc.tailParticles.forEach(({ mesh, offset }) => {
          const tailProg = (arc.progress - offset + 1) % 1;
          mesh.position.copy(arc.curve.getPointAt(tailProg));
        });
      });

      renderer.render(scene, camera);
    };

    animate();

    // 14. Cleanup
    return () => {
      cancelAnimationFrame(animationFrameId);
      container.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
      container.removeEventListener('wheel', onWheel);
      renderer.dispose();
    };
  }, [visiblePoints, autoRotate, speedMultiplier]);

  // Focus camera/globe rotation to specific point
  const handleFocusPoint = (pt) => {
    if (!globeGroupRef.current || !pt) return;
    const phi = (90 - pt.lat) * (Math.PI / 180);
    const targetRotY = -((pt.lon + 180) * (Math.PI / 180)) + Math.PI / 2;
    globeGroupRef.current.rotation.y = targetRotY;
    globeGroupRef.current.rotation.x = Math.max(-0.6, Math.min(0.6, (pt.lat * Math.PI) / 180));
    setSelectedDossier(pt);
    tacticalAudio.playRadarPing();
  };

  // Reset rotation to SOC HQ (New Delhi) without opening threat dossier
  const handleResetToHQ = () => {
    if (!globeGroupRef.current) return;
    const targetRotY = -((SOC_COORDS.lon + 180) * (Math.PI / 180)) + Math.PI / 2;
    globeGroupRef.current.rotation.y = targetRotY;
    globeGroupRef.current.rotation.x = Math.max(-0.6, Math.min(0.6, (SOC_COORDS.lat * Math.PI) / 180));
    setSelectedDossier(null);
    tacticalAudio.playRadarPing();
    toast.success('Centered on SOC Defense Base (HQ)', { icon: '🎯' });
  };

  return (
    <div className="relative w-full overflow-hidden select-none bg-[#030712] rounded-xl border border-surface-700/80 shadow-2xl">
      {/* 3D WebGL Canvas */}
      <div
        ref={containerRef}
        className="w-full cursor-grab active:cursor-grabbing flex justify-center"
        style={{ minHeight: '480px' }}
      />

      {/* Top Tactical HUD Bar */}
      <div className="absolute top-3 left-3 right-3 flex items-center justify-between pointer-events-none">
        <div className="flex items-center gap-2 font-mono text-[11px] bg-surface-900/90 px-3 py-1.5 rounded-lg border border-cyan-500/30 text-cyan-300 backdrop-blur shadow-lg pointer-events-auto">
          <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
          <span className="font-bold tracking-wider">DEFENSE GRID 3D DIGITAL TWIN</span>
          <span className="text-slate-600">|</span>
          <span className="text-slate-400">HQ: NEW DELHI (28.61°N, 77.21°E)</span>
        </div>

        {/* DEFCON Status Pill */}
        <div className="flex items-center gap-2 pointer-events-auto">
          <div
            className={`px-3 py-1.5 rounded-lg font-mono text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 border shadow-lg backdrop-blur ${
              stats.defcon === 1
                ? 'bg-red-950/90 border-red-500 text-red-300 animate-pulse shadow-red-950/60'
                : stats.defcon === 2
                ? 'bg-orange-950/90 border-orange-500 text-orange-300'
                : 'bg-emerald-950/90 border-emerald-500 text-emerald-300'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>DEFCON {stats.defcon} : {stats.defcon <= 2 ? 'ELEVATED THREAT' : 'GUARDED'}</span>
          </div>

          {/* Reset to SOC Base */}
          <button
            onClick={handleResetToHQ}
            className="p-1.5 rounded-lg bg-surface-900/90 border border-surface-700 text-slate-300 hover:text-cyan-300 hover:border-cyan-500/50 transition-colors shadow-lg"
            title="Recenter camera on SOC Defense Base"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Interactive Controls Overlay (Bottom Left) */}
      <div className="absolute bottom-3 left-3 flex flex-wrap items-center gap-2 pointer-events-auto">
        {/* Auto-Rotation Toggle */}
        <button
          onClick={() => setAutoRotate(!autoRotate)}
          className={`px-2.5 py-1 rounded-lg text-xs font-mono font-medium border transition-colors flex items-center gap-1.5 ${
            autoRotate
              ? 'bg-cyan-950/80 border-cyan-700/60 text-cyan-300'
              : 'bg-surface-900/90 border-surface-700 text-slate-400 hover:text-slate-200'
          }`}
        >
          <Compass className={`w-3.5 h-3.5 ${autoRotate ? 'animate-spin-slow text-cyan-400' : ''}`} />
          <span>Orbit: {autoRotate ? 'ON' : 'PAUSED'}</span>
        </button>

        {/* Tactical Warp Speed */}
        <div className="flex bg-surface-900/90 border border-surface-700 rounded-lg p-0.5 text-xs font-mono">
          {[1, 2, 4].map((s) => (
            <button
              key={s}
              onClick={() => setSpeedMultiplier(s)}
              className={`px-2 py-0.5 rounded transition-colors ${
                speedMultiplier === s
                  ? 'bg-cyan-950 border border-cyan-700/60 text-cyan-300 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {s}x
            </button>
          ))}
        </div>

        {/* Severity Quick Filters */}
        <div className="flex bg-surface-900/90 border border-surface-700 rounded-lg p-0.5 text-xs font-mono">
          {['all', 'critical', 'high'].map((f) => (
            <button
              key={f}
              onClick={() => setActiveFilter(f)}
              className={`px-2 py-0.5 rounded capitalize transition-colors ${
                activeFilter === f
                  ? 'bg-surface-700 text-slate-100 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Top Attack Corridors Strip (Bottom Right) */}
      <div className="absolute bottom-3 right-3 hidden lg:flex items-center gap-1.5 font-mono text-[11px] bg-surface-900/90 p-1.5 rounded-lg border border-surface-700/80 backdrop-blur pointer-events-auto">
        <span className="text-slate-500 uppercase px-1 text-[10px] font-semibold">Active Corridors:</span>
        {topCorridors.map(([name, count]) => (
          <button
            key={name}
            onClick={() => {
              const matched = points.find((p) => p.country === name || `${p.city}, ${p.country}` === name);
              if (matched) handleFocusPoint(matched);
            }}
            className="px-2 py-0.5 rounded bg-surface-800 hover:bg-surface-700 border border-surface-700 text-slate-300 hover:text-cyan-300 transition-colors flex items-center gap-1"
          >
            <span>{name}</span>
            <span className="text-[10px] text-red-400 font-bold">({count})</span>
          </button>
        ))}
      </div>

      {/* Hover Tooltip (Raycasting) */}
      {hoveredData && !selectedDossier && (
        <div
          className="absolute z-30 pointer-events-none bg-surface-950/95 border border-cyan-500/70 rounded-xl shadow-2xl p-3 text-xs backdrop-blur font-sans max-w-[260px] animate-fade-in"
          style={{
            left: `${Math.min(80, Math.max(15, (hoveredData.screenX / (containerRef.current?.clientWidth || 920)) * 100))}%`,
            top: `${Math.max(8, (hoveredData.screenY / 480) * 100 - 12)}%`,
            transform: 'translate(-50%, -100%)',
          }}
        >
          <div className="flex items-center justify-between mb-1">
            <div className="flex items-center gap-1.5 font-mono font-bold text-slate-100">
              <span
                className={`w-2 h-2 rounded-full ${
                  hoveredData.severity === 'critical' ? 'bg-red-400 animate-pulse' : 'bg-orange-400'
                }`}
              />
              <span className="truncate">{hoveredData.ip}</span>
            </div>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-surface-800 text-slate-300 border border-surface-700">
              {hoveredData.severity}
            </span>
          </div>
          <p className="text-[11px] text-slate-200">
            📍 {hoveredData.city ? `${hoveredData.city}, ` : ''}{hoveredData.country}
          </p>
          <p className="text-[10px] text-slate-400 truncate">
            ISP: {hoveredData.isp}
          </p>
          <p className="text-[10px] text-cyan-400 font-semibold mt-1">
            {getHumanThreat(hoveredData.type).title}
          </p>
          <p className="text-[9px] text-slate-500 font-mono mt-1 border-t border-surface-800 pt-1">
            Click to inspect telemetry & SOAR countermeasure
          </p>
        </div>
      )}

      {/* Detailed Tactical Threat Dossier Card (Expanded on Pin Click) */}
      {selectedDossier && (
        <div className="absolute top-14 right-3 z-30 w-80 bg-surface-950/95 border border-cyan-500/80 rounded-xl shadow-2xl p-4 text-xs backdrop-blur-md font-sans animate-fade-in pointer-events-auto">
          <div className="flex items-center justify-between border-b border-surface-800 pb-2.5 mb-2.5">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-red-950/80 border border-red-800/60 text-red-400">
                <Flame className="w-4 h-4 animate-pulse" />
              </div>
              <div>
                <h3 className="font-mono font-bold text-slate-100 uppercase tracking-wide text-xs">
                  Threat Vector Dossier
                </h3>
                <span className="text-[10px] text-slate-400 font-mono">
                  {selectedDossier.ip}
                </span>
              </div>
            </div>
            <button
              onClick={() => setSelectedDossier(null)}
              className="p-1 rounded hover:bg-surface-800 text-slate-400 hover:text-slate-200 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="space-y-2 font-mono text-[11px]">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Classification:</span>
              <span className="text-cyan-300 font-bold truncate max-w-[170px]">
                {getHumanThreat(selectedDossier.type).title}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-400">Severity Tier:</span>
              <span
                className={`px-1.5 py-0.2 rounded uppercase text-[10px] font-bold ${
                  selectedDossier.severity === 'critical'
                    ? 'bg-red-950 text-red-400 border border-red-800'
                    : 'bg-orange-950 text-orange-400 border border-orange-800'
                }`}
              >
                {selectedDossier.severity}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-400">Origin Location:</span>
              <span className="text-slate-200">
                {selectedDossier.city ? `${selectedDossier.city}, ` : ''}{selectedDossier.country}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-400">Geo Coordinates:</span>
              <span className="text-slate-300">
                {selectedDossier.lat?.toFixed(2)}°N, {selectedDossier.lon?.toFixed(2)}°E
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-400">Transit Distance:</span>
              <span className="text-amber-400 font-bold">
                {calculateDistanceKm(
                  selectedDossier.lat,
                  selectedDossier.lon,
                  SOC_COORDS.lat,
                  SOC_COORDS.lon
                ).toLocaleString()} km to HQ
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-400">Autonomous System:</span>
              <span className="text-slate-300 truncate max-w-[160px]">
                {selectedDossier.isp || 'Backbone AS'}
              </span>
            </div>
          </div>

          {/* Action Containment Button */}
          <div className="mt-3.5 pt-2.5 border-t border-surface-800 flex items-center justify-between gap-2">
            <button
              onClick={() => handleFocusPoint(selectedDossier)}
              className="px-2.5 py-1.5 rounded-lg border border-surface-700 bg-surface-900 text-slate-300 hover:text-cyan-300 text-xs font-mono transition-colors flex items-center gap-1"
            >
              <Crosshair className="w-3.5 h-3.5" />
              <span>Center Orbit</span>
            </button>

            {selectedDossier.label === SOC_COORDS.label || (!selectedDossier.ip && !selectedDossier.pid) || selectedDossier.ip === 'Attacker Node' ? (
              <div className="flex-1 px-3 py-1.5 rounded-lg font-mono text-[11px] bg-cyan-950/70 border border-cyan-700/60 text-cyan-300 text-center flex items-center justify-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-cyan-400" />
                <span>Protected Node</span>
              </div>
            ) : (
              <button
                onClick={() => handleContainTarget(selectedDossier)}
                disabled={isContaining}
                className="flex-1 px-3 py-1.5 rounded-lg font-mono font-bold text-xs bg-red-700 hover:bg-red-600 text-white shadow-lg shadow-red-950/60 transition-all flex items-center justify-center gap-1.5"
              >
                <Zap className="w-3.5 h-3.5 fill-current" />
                <span>{isContaining ? 'Neutralizing...' : 'Block via SOAR'}</span>
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
