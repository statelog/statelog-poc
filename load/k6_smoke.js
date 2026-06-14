import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 5,
  duration: '20s',
  thresholds: {
    http_req_duration: ['p(95)<300'],
  },
};

export default function () {
  const res = http.get('http://127.0.0.1:8000/healthz');
  check(res, { 'healthz 200': (r) => r.status === 200 });
  sleep(1);
}
