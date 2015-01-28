# Copyright 2013 Big Switch Networks, Inc.
# All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.


import contextlib

import mock
from webob import exc

from neutron import context
from neutron.extensions import firewall
from neutron.plugins.common import constants as const
from neutron.services.firewall import fwaas_plugin
from neutron.tests import base
from neutron.tests.unit import test_l3_plugin
from neutron.tests.unit.db.firewall import test_db_firewall


FW_PLUGIN_KLASS = (
    "neutron.services.firewall.fwaas_plugin.FirewallPlugin"
)


class TestFirewallCallbacks(test_db_firewall.FirewallPluginDbTestCase,
                            test_l3_plugin.L3NatTestCaseMixin):

    def setUp(self):
        super(TestFirewallCallbacks,
              self).setUp(fw_plugin=FW_PLUGIN_KLASS)
        self.callbacks = self.plugin.endpoints[0]

    def test_set_firewall_status(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.router() as r:
                with self.firewall(firewall_policy_id=fwp_id,
                                   admin_state_up=
                                   test_db_firewall.ADMIN_STATE_UP,
                                   router_ids=[r['router']['id']]) as fw:
                    fw_id = fw['firewall']['id']
                    res = self.callbacks.set_firewall_status(ctx, fw_id,
                                                             const.ACTIVE,
                                                             host='dummy')
                    fw_db = self.plugin.get_firewall(ctx, fw_id)
                    self.assertEqual(fw_db['status'], const.ACTIVE)
                    self.assertTrue(res)
                    res = self.callbacks.set_firewall_status(ctx, fw_id,
                                                             const.ERROR)
                    fw_db = self.plugin.get_firewall(ctx, fw_id)
                    self.assertEqual(fw_db['status'], const.ERROR)
                    self.assertFalse(res)

    def test_set_firewall_status_pending_delete(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.router() as r:
                with self.firewall(firewall_policy_id=fwp_id,
                                   admin_state_up=
                                   test_db_firewall.ADMIN_STATE_UP,
                                   router_ids=[r['router']['id']]) as fw:
                    fw_id = fw['firewall']['id']
                    fw_db = self.plugin._get_firewall(ctx, fw_id)
                    fw_db['status'] = const.PENDING_DELETE
                    ctx.session.flush()
                    res = self.callbacks.set_firewall_status(ctx, fw_id,
                                                             const.ACTIVE,
                                                             host='dummy')
                    fw_db = self.plugin.get_firewall(ctx, fw_id)
                    self.assertEqual(fw_db['status'], const.PENDING_DELETE)
                    self.assertFalse(res)

    def test_firewall_deleted(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.router() as r:
                with self.firewall(firewall_policy_id=fwp_id,
                                   admin_state_up=test_db_firewall
                                   .ADMIN_STATE_UP,
                                   do_delete=False,
                                   router_ids=[r['router']['id']]) as fw:
                    fw_id = fw['firewall']['id']
                    with ctx.session.begin(subtransactions=True):
                        fw_db = self.plugin._get_firewall(ctx, fw_id)
                        fw_db['status'] = const.PENDING_DELETE
                        ctx.session.flush()
                        res = self.callbacks.firewall_deleted(ctx, fw_id,
                                                              host='dummy')
                        self.assertTrue(res)
                        self.assertRaises(firewall.FirewallNotFound,
                                          self.plugin.get_firewall,
                                          ctx, fw_id)

    def test_firewall_deleted_error(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.router() as r:
                with self.firewall(
                    firewall_policy_id=fwp_id,
                    admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                    router_ids=[r['router']['id']]
                ) as fw:
                    fw_id = fw['firewall']['id']
                    res = self.callbacks.firewall_deleted(ctx, fw_id,
                                                          host='dummy')
                    self.assertFalse(res)
                    fw_db = self.plugin._get_firewall(ctx, fw_id)
                    self.assertEqual(fw_db['status'], const.ERROR)

    def test_get_firewall_for_tenant(self):
        tenant_id = 'test-tenant'
        ctx = context.Context('', tenant_id)
        with contextlib.nested(self.firewall_rule(name='fwr1',
                                                  tenant_id=tenant_id),
                               self.firewall_rule(name='fwr2',
                                                  tenant_id=tenant_id),
                               self.firewall_rule(name='fwr3',
                                                  tenant_id=tenant_id)
                               ) as fr:
            with self.firewall_policy(tenant_id=tenant_id) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                res = req.get_response(self.ext_api)
                attrs = self._get_test_firewall_attrs()
                attrs['firewall_policy_id'] = fwp_id
                with self.router() as r:
                    with self.firewall(firewall_policy_id=fwp_id,
                                       tenant_id=tenant_id,
                                       admin_state_up=
                                       test_db_firewall.ADMIN_STATE_UP,
                                       router_ids=[r['router']['id']]
                                       ) as fw:
                        fw_id = fw['firewall']['id']
                        res = (self.callbacks
                                   .get_firewalls_for_tenant(ctx,
                                                             host='dummy'))
                        fw_rules = (
                            self.plugin._make_firewall_dict_with_rules(ctx,
                                                                       fw_id)
                        )
                        self.assertEqual(res[0], fw_rules)
                        self._compare_firewall_rule_lists(
                            fwp_id, fr, res[0]['firewall_rule_list'])

    def test_get_firewall_for_tenant_without_rules(self):
        tenant_id = 'test-tenant'
        ctx = context.Context('', tenant_id)
        with self.firewall_policy(tenant_id=tenant_id) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs = self._get_test_firewall_attrs()
            attrs['firewall_policy_id'] = fwp_id
            with self.router() as r:
                attrs['router_ids'] = [r['router']['id']]
                with self.firewall(firewall_policy_id=fwp_id,
                                   tenant_id=tenant_id,
                                   admin_state_up=
                                   test_db_firewall.ADMIN_STATE_UP,
                                   router_ids=[r['router']['id']]
                                   ) as fw:
                        fw_list = [fw['firewall']]
                        f = (self.callbacks.
                             get_firewalls_for_tenant_without_rules)
                        res = f(ctx, host='dummy')
                        for fw in res:
                            del fw['shared']
                        self.assertEqual(res, fw_list)


class TestFirewallAgentApi(base.BaseTestCase):
    def setUp(self):
        super(TestFirewallAgentApi, self).setUp()

        self.api = fwaas_plugin.FirewallAgentApi('topic', 'host')
        self.mock_fanoutcast = mock.patch.object(self.api,
                                                 'fanout_cast').start()
        self.mock_msg = mock.patch.object(self.api, 'make_msg').start()

    def test_init(self):
        self.assertEqual(self.api.topic, 'topic')
        self.assertEqual(self.api.host, 'host')

    def _call_test_helper(self, method_name):
        rv = getattr(self.api, method_name)(mock.sentinel.context, 'test')
        self.assertEqual(rv, self.mock_fanoutcast.return_value)
        self.mock_fanoutcast.assert_called_once_with(
            mock.sentinel.context,
            self.mock_msg.return_value
        )

        self.mock_msg.assert_called_once_with(
            method_name,
            firewall='test',
            host='host'
        )

    def test_create_firewall(self):
        self._call_test_helper('create_firewall')

    def test_update_firewall(self):
        self._call_test_helper('update_firewall')

    def test_delete_firewall(self):
        self._call_test_helper('delete_firewall')


class TestFirewallPluginBase(test_db_firewall.TestFirewallDBPlugin):

    def setUp(self):
        super(TestFirewallPluginBase, self).setUp(fw_plugin=FW_PLUGIN_KLASS)
        self.callbacks = self.plugin.endpoints[0]

    def test_create_firewall_admin_not_affected_by_other_tenant(self):
        # Create fw with admin after creating fw with other tenant
        with self.router(tenant_id='other-tenant') as r1:
            with self.router() as r2:
                with self.firewall(tenant_id='other-tenant',
                                   router_ids=[r1['router']['id']]) as fw1:
                    with self.firewall(router_ids=[r2['router']['id']]) as fw2:
                        self.assertEqual('other-tenant',
                                         fw1['firewall']['tenant_id'])
                        self.assertEqual(self._tenant_id,
                                         fw2['firewall']['tenant_id'])

    def test_create_firewall_fails_when_fake_router_ids(self):
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            tenant_id = fwp['firewall_policy']['tenant_id']
            with self.router() as r:
                real_router_id = r['router']['id']
                fake_router_id_1 = '550e8400-e29b-41d4-a716-446655440000'
                fake_router_id_2 = '94fecd16-b5ce-11e4-a71e-12e3f512a338'
                data = {'firewall': {'tenant_id': tenant_id,
                                     'router_ids': [real_router_id,
                                                    fake_router_id_1,
                                                    fake_router_id_2],
                                     'firewall_policy_id': fwp_id}}
                req = self.new_create_request('firewalls', data)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, exc.HTTPConflict.code)

    def test_create_firewall_fails_when_router_is_busy(self):
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.router() as r:
                r_id = r['router']['id']
                with self.firewall(router_ids=[r_id]) as fw:
                    tenant_id = fw['firewall']['tenant_id']
                    data = {'firewall': {'router_ids': [r_id],
                                         'tenant_id': tenant_id,
                                         'firewall_policy_id': fwp_id}}
                    req = self.new_create_request('firewalls', data)
                    res = req.get_response(self.ext_api)
                    self.assertEqual(res.status_int, exc.HTTPConflict.code)

    def test_create_second_firewall_permitted(self):
        with contextlib.nested(self.router(),
                               self.router()) as routers:
            r1_id = routers[0]['router']['id']
            r2_id = routers[1]['router']['id']
            with contextlib.nested(self.firewall(router_ids=[r1_id]),
                                   self.firewall(router_ids=[r2_id])) as fws:
                fw1_tenant_id = fws[0]['firewall']['tenant_id']
                fw2_tenant_id = fws[1]['firewall']['tenant_id']
                self.assertEqual(self._tenant_id,
                                 fw1_tenant_id)
                self.assertEqual(self._tenant_id,
                                 fw2_tenant_id)

    def test_update_firewall(self):
        ctx = context.get_admin_context()
        name = "new_firewall1"
        attrs = self._get_test_firewall_attrs(name)

        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['firewall_policy_id'] = fwp_id
            with self.router() as r:
                r_id = r['router']['id']
                attrs['router_ids'] = [r_id]
                with self.firewall(firewall_policy_id=fwp_id,
                                   admin_state_up=
                                   test_db_firewall.ADMIN_STATE_UP,
                                   router_ids=[r_id]) as firewall:
                    fw_id = firewall['firewall']['id']
                    res = self.callbacks.set_firewall_status(ctx, fw_id,
                                                             const.ACTIVE)
                    data = {'firewall': {'name': name}}
                    req = self.new_update_request('firewalls', data, fw_id)
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.ext_api))
                    attrs = self._replace_firewall_status(attrs,
                                                          const.PENDING_CREATE,
                                                          const.PENDING_UPDATE)
                    for k, v in attrs.iteritems():
                        self.assertEqual(res['firewall'][k], v)

    def test_update_firewall_router_ids(self):
        attrs = self._get_test_firewall_attrs()
        with contextlib.nested(self.router(),
                               self.router()) as rs:
            r1_id = rs[0]['router']['id']
            r2_id = rs[1]['router']['id']
            with self.firewall(router_ids=[r1_id]) as fw:
                fw_id = fw['firewall']['id']
                name = 'new_firewall_name'
                data = {'firewall': {'name': name,
                                     'router_ids': [r1_id, r2_id]}}
                ctx = context.get_admin_context()
                self.callbacks.set_firewall_status(ctx, fw_id, const.ACTIVE)
                req = self.new_update_request('firewalls', data, fw_id)
                attrs['name'] = name
                attrs['router_ids'] = [r1_id, r2_id]
                updated_fw = self.deserialize(self.fmt,
                                              req.get_response(self.ext_api))
                attrs['router_ids'].sort()
                updated_fw['firewall']['router_ids'].sort()
                attrs = self._replace_firewall_status(attrs,
                                                      const.PENDING_CREATE,
                                                      const.PENDING_UPDATE)
                for k, v in attrs.iteritems():
                    self.assertEqual(updated_fw['firewall'][k], v)

    def test_update_firewall_fails_when_fake_router_ids(self):
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.router() as r:
                real_router_id = r['router']['id']
                fake_router_id_1 = '550e8400-e29b-41d4-a716-446655440000'
                fake_router_id_2 = '94fecd16-b5ce-11e4-a71e-12e3f512a338'
                with self.firewall(router_ids=[real_router_id]) as fw:
                    fw_id = fw['firewall']['id']
                    data = {'firewall': {'router_ids': [real_router_id,
                                                        fake_router_id_1,
                                                        fake_router_id_2],
                                         'firewall_policy_id': fwp_id}}
                    req = self.new_update_request('firewalls', data, fw_id)
                    res = req.get_response(self.ext_api)
                    self.assertEqual(res.status_int, exc.HTTPConflict.code)

    def test_update_firewall_fails_when_firewall_pending(self):
        name = "new_firewall1"
        attrs = self._get_test_firewall_attrs(name)

        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['firewall_policy_id'] = fwp_id
            with self.router() as r:
                with self.firewall(firewall_policy_id=fwp_id,
                                   admin_state_up=
                                   test_db_firewall.ADMIN_STATE_UP,
                                   router_ids=[r['router']['id']]) as firewall:
                    fw_id = firewall['firewall']['id']
                    data = {'firewall': {'name': name}}
                    req = self.new_update_request('firewalls', data, fw_id)
                    res = req.get_response(self.ext_api)
                    self.assertEqual(res.status_int, exc.HTTPConflict.code)

    def test_update_firewall_fails_when_router_is_busy(self):
        with contextlib.nested(self.router(),
                               self.router()) as rs:
            r1_id = rs[0]['router']['id']
            r2_id = rs[1]['router']['id']
            with contextlib.nested(self.firewall(router_ids=[r1_id]),
                                   self.firewall(router_ids=[r2_id])) as fws:
                fw1_id = fws[0]['firewall']['id']
                data = {'firewall': {'router_ids': [r2_id]}}
                req = self.new_update_request('firewalls', data, fw1_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, exc.HTTPConflict.code)

    def test_update_firewall_shared_fails_for_non_admin(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.router() as r:
                with self.firewall(firewall_policy_id=fwp_id,
                                   admin_state_up=
                                   test_db_firewall.ADMIN_STATE_UP,
                                   tenant_id='noadmin',
                                   router_ids=[r['router']['id']]) as firewall:
                    fw_id = firewall['firewall']['id']
                    self.callbacks.set_firewall_status(ctx, fw_id,
                                                       const.ACTIVE)
                    data = {'firewall': {'shared': True}}
                    req = self.new_update_request(
                        'firewalls', data, fw_id,
                        context=context.Context('', 'noadmin'))
                    res = req.get_response(self.ext_api)
                    self.assertEqual(res.status_int, exc.HTTPForbidden.code)

    def test_update_firewall_policy_fails_when_firewall_pending(self):
        name = "new_firewall1"
        attrs = self._get_test_firewall_attrs(name)

        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['firewall_policy_id'] = fwp_id
            with self.router() as r:
                with self.firewall(firewall_policy_id=fwp_id,
                                   admin_state_up=
                                   test_db_firewall.ADMIN_STATE_UP,
                                   router_ids=[r['router']['id']]):
                    data = {'firewall_policy': {'name': name}}
                    req = self.new_update_request('firewall_policies',
                                                  data, fwp_id)
                    res = req.get_response(self.ext_api)
                    self.assertEqual(res.status_int, exc.HTTPConflict.code)

    def test_update_firewall_rule_fails_when_firewall_pending(self):
        with self.firewall_rule(name='fwr1') as fr:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                fr_id = fr['firewall_rule']['id']
                fw_rule_ids = [fr_id]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                req.get_response(self.ext_api)
                with self.router() as r:
                    with self.firewall(firewall_policy_id=fwp_id,
                                       admin_state_up=
                                       test_db_firewall.ADMIN_STATE_UP,
                                       router_ids=[r['router']['id']]):
                        data = {'firewall_rule': {'protocol': 'udp'}}
                        req = self.new_update_request('firewall_rules',
                                                      data, fr_id)
                        res = req.get_response(self.ext_api)
                        self.assertEqual(res.status_int, exc.HTTPConflict.code)

    def test_delete_firewall(self):
        ctx = context.get_admin_context()
        attrs = self._get_test_firewall_attrs()
        # stop the AgentRPC patch for this one to test pending states
        self.agentapi_delf_p.stop()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['firewall_policy_id'] = fwp_id
            with self.router() as r:
                with self.firewall(firewall_policy_id=fwp_id,
                                   admin_state_up=
                                   test_db_firewall.ADMIN_STATE_UP,
                                   router_ids=[r['router']['id']]) as firewall:
                    fw_id = firewall['firewall']['id']
                    attrs = self._replace_firewall_status(attrs,
                                                          const.PENDING_CREATE,
                                                          const.PENDING_DELETE)
                    req = self.new_delete_request('firewalls', fw_id)
                    req.get_response(self.ext_api)
                    fw_db = self.plugin._get_firewall(ctx, fw_id)
                    for k, v in attrs.iteritems():
                        self.assertEqual(fw_db[k], v)
                # cleanup the pending firewall
                self.plugin.endpoints[0].firewall_deleted(ctx, fw_id)

    def test_delete_firewall_after_agent_delete(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.router() as r:
                with self.firewall(firewall_policy_id=fwp_id,
                                   do_delete=False,
                                   router_ids=[r['router']['id']]) as fw:
                    fw_id = fw['firewall']['id']
                    req = self.new_delete_request('firewalls', fw_id)
                    res = req.get_response(self.ext_api)
                    self.assertEqual(res.status_int, exc.HTTPNoContent.code)
                    self.assertRaises(firewall.FirewallNotFound,
                                      self.plugin.get_firewall,
                                      ctx, fw_id)

    def test_make_firewall_dict_with_in_place_rules(self):
        ctx = context.get_admin_context()
        with contextlib.nested(self.firewall_rule(name='fwr1'),
                               self.firewall_rule(name='fwr2'),
                               self.firewall_rule(name='fwr3')) as fr:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                req.get_response(self.ext_api)
                attrs = self._get_test_firewall_attrs()
                attrs['firewall_policy_id'] = fwp_id
                with self.router() as r:
                    with self.firewall(firewall_policy_id=fwp_id,
                                       admin_state_up=
                                       test_db_firewall.ADMIN_STATE_UP,
                                       router_ids=[r['router']['id']]) as fw:
                        fw_id = fw['firewall']['id']
                        fw_rules = (
                            self.plugin._make_firewall_dict_with_rules(ctx,
                                                                       fw_id)
                        )
                        self.assertEqual(fw_rules['id'], fw_id)
                        self._compare_firewall_rule_lists(
                            fwp_id, fr, fw_rules['firewall_rule_list'])

    def test_make_firewall_dict_with_in_place_rules_no_policy(self):
        ctx = context.get_admin_context()
        with self.router() as r:
            with self.firewall(router_ids=[r['router']['id']]) as fw:
                fw_id = fw['firewall']['id']
                fw_rules = self.plugin._make_firewall_dict_with_rules(ctx,
                                                                      fw_id)
                self.assertEqual(fw_rules['firewall_rule_list'], [])

    def test_list_firewalls(self):
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.router() as r:
                with self.firewall(name='fw1', firewall_policy_id=fwp_id,
                                   description='fw',
                                   router_ids=[r['router']['id']]) as fwalls:
                    self._test_list_resources('firewall', [fwalls],
                                              query_params='description=fw')
