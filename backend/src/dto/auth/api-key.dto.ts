import { IsArray, IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class GenerateApiKeyDto {
  @ApiProperty({
    description: 'List of permission scopes for the API key',
    example: ['read', 'write', 'admin'],
    required: false,
    isArray: true,
    default: ['default'],
  })
  @IsArray()
  @IsOptional()
  scopes?: string[];

  @ApiProperty({
    description: 'Human-readable description of the API key purpose',
    example: 'Integration with CRM system',
    required: false,
  })
  @IsString()
  @IsOptional()
  description?: string;
}

export class RotateApiKeyDto {
  @ApiProperty({
    description: 'ID of the API key to rotate',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  @IsString()
  apiKeyId: string;

  @ApiProperty({
    description: 'Updated list of permission scopes for the API key',
    example: ['read', 'write', 'admin'],
    required: false,
    isArray: true,
  })
  @IsArray()
  @IsOptional()
  scopes?: string[];

  @ApiProperty({
    description: 'Updated description of the API key purpose',
    example: 'Integration with updated CRM system',
    required: false,
  })
  @IsString()
  @IsOptional()
  description?: string;
}
