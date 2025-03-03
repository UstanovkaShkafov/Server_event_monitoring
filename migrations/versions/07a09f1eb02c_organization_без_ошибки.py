"""organization без ошибки

Revision ID: 07a09f1eb02c
Revises: b88fa23e4a55
Create Date: 2025-02-21 22:26:49.071064

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '07a09f1eb02c'
down_revision: Union[str, None] = 'b88fa23e4a55'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index('ix_incident_id', table_name='incident')
    op.drop_table('incident')
    op.drop_index('ix_user_id', table_name='user')
    op.drop_index('ix_user_name', table_name='user')
    op.drop_index('ix_user_organiztion', table_name='user')
    op.drop_index('ix_user_sername', table_name='user')
    op.drop_index('ix_user_username', table_name='user')
    op.drop_table('user')
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.INTEGER(), server_default=sa.text("nextval('user_id_seq'::regclass)"), autoincrement=True, nullable=False),
    sa.Column('username', sa.VARCHAR(), autoincrement=False, nullable=True),
    sa.Column('hashed_password', sa.VARCHAR(), autoincrement=False, nullable=False),
    sa.Column('name', sa.VARCHAR(), autoincrement=False, nullable=True),
    sa.Column('sername', sa.VARCHAR(), autoincrement=False, nullable=True),
    sa.Column('organiztion', sa.VARCHAR(), autoincrement=False, nullable=True),
    sa.Column('is_active', sa.BOOLEAN(), autoincrement=False, nullable=True),
    sa.Column('role', postgresql.ENUM('admin', 'user', name='roleenum'), autoincrement=False, nullable=True),
    sa.Column('telegram_id', sa.VARCHAR(), autoincrement=False, nullable=True),
    sa.PrimaryKeyConstraint('id', name='user_pkey'),
    sa.UniqueConstraint('telegram_id', name='user_telegram_id_key'),
    postgresql_ignore_search_path=False
    )
    op.create_index('ix_user_username', 'user', ['username'], unique=True)
    op.create_index('ix_user_sername', 'user', ['sername'], unique=False)
    op.create_index('ix_user_organiztion', 'user', ['organiztion'], unique=False)
    op.create_index('ix_user_name', 'user', ['name'], unique=False)
    op.create_index('ix_user_id', 'user', ['id'], unique=False)
    op.create_table('incident',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(), autoincrement=False, nullable=True),
    sa.Column('organization', sa.VARCHAR(), autoincrement=False, nullable=False),
    sa.Column('field', sa.VARCHAR(), autoincrement=False, nullable=False),
    sa.Column('event_area', sa.VARCHAR(), autoincrement=False, nullable=False),
    sa.Column('event_type', sa.VARCHAR(), autoincrement=False, nullable=False),
    sa.Column('description', sa.TEXT(), autoincrement=False, nullable=True),
    sa.Column('consequences', sa.TEXT(), autoincrement=False, nullable=True),
    sa.Column('comments', sa.TEXT(), autoincrement=False, nullable=True),
    sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], name='incident_user_id_fkey'),
    sa.PrimaryKeyConstraint('id', name='incident_pkey')
    )
    op.create_index('ix_incident_id', 'incident', ['id'], unique=False)
    # ### end Alembic commands ###
