/**
 * Alert Lambda
 * Triggered by CloudWatch Alarms (DLQ messages, errors) → publishes to SNS
 */
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';

const sns = new SNSClient({});
const TOPIC_ARN = process.env.SNS_TOPIC_ARN;

export const handler = async (event) => {
  const alarmName = event.alarmName || event.detail?.alarmName || 'Unknown Alarm';
  const reason = event.newStateReason || event.detail?.state?.reason || JSON.stringify(event);

  const message = {
    alert_type: 'system',
    alarm: alarmName,
    reason,
    timestamp: new Date().toISOString()
  };

  if (TOPIC_ARN) {
    await sns.send(new PublishCommand({
      TopicArn: TOPIC_ARN,
      Subject: `⚠️ System Alert: ${alarmName}`,
      Message: JSON.stringify(message, null, 2)
    }));
  }

  console.log('Alert sent:', message);
  return { statusCode: 200, body: 'Alert processed' };
};