<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20250826233348 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // Create 'user' table used by App\Entity\User
        $this->addSql('CREATE TABLE user (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            email VARCHAR(180) NOT NULL,
            password VARCHAR(255) NOT NULL,
            roles CLOB NOT NULL -- (DC2Type:json)
        );');

        // Additional nullable fields used in the app
        $this->addSql('ALTER TABLE user ADD COLUMN nom_complete VARCHAR(255) DEFAULT NULL');
        $this->addSql('ALTER TABLE user ADD COLUMN tel VARCHAR(255) DEFAULT NULL');
        $this->addSql('ALTER TABLE user ADD COLUMN type VARCHAR(50) DEFAULT NULL');

    }

    public function down(Schema $schema): void
    {
    $this->addSql('DROP TABLE user');

    }
}
