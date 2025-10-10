from rest_framework import serializers
from .models import Call

class CallSerializer(serializers.ModelSerializer):
    class Meta:
        model = Call
        fields = ['id', 'user', 'call_type', 'scheduled_time', 'voice_record', 'notification_sent', 'created_at', 'updated_at']
        read_only_fields = ['user', 'created_at', 'updated_at']

    def validate(self, data):
        # Ensure voice_record is only provided for AI calls
        if data['call_type'] == 'AI' and not data.get('voice_record'):
            raise serializers.ValidationError("Voice record is required for AI calls.")
        if data['call_type'] == 'Human' and data.get('voice_record'):
            raise serializers.ValidationError("Voice record should not be provided for Human calls.")
        return data
