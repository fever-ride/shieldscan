/**
 * CloudWatch Embedded Metric Format (EMF) helper.
 * Emitting is just a console.log — Lambda's log agent parses the JSON and
 * creates custom CloudWatch metrics automatically. No SDK or IAM changes needed.
 *
 * Usage:
 *   emitMetric('scans_total', 1, { scan_type: 'sast', status: 'completed' });
 *   emitMetric('scan_duration_ms', 1234, { scan_type: 'sast' }, 'Milliseconds');
 */
export function emitMetric(metricName, value, dimensions = {}, unit = 'Count') {
  const dimensionKeys = Object.keys(dimensions);
  const record = {
    _aws: {
      Timestamp: Date.now(),
      CloudWatchMetrics: [{
        Namespace:  'ShieldScan',
        Dimensions: [dimensionKeys],
        Metrics:    [{ Name: metricName, Unit: unit }],
      }],
    },
    [metricName]: value,
    ...dimensions,
  };
  console.log(JSON.stringify(record));
}
