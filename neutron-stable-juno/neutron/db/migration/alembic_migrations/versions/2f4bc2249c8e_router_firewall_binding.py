# Copyright 2015 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

"""empty message

Revision ID: 2f4bc2249c8e
Revises: 176511d61aab
Create Date: 2015-02-05 16:50:15.548167

"""

# revision identifiers, used by Alembic.
revision = '2f4bc2249c8e'
down_revision = '176511d61aab'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'router_firewall_bindings',
        sa.Column('router_id', sa.String(length=255), nullable=False),
        sa.Column('firewall_id', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['firewall_id'], ['firewalls.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id')
    )


def downgrade():
    op.drop_table('router_firewall_bindings')
