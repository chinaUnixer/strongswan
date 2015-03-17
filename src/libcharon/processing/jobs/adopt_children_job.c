/*
 * Copyright (C) 2015 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
 *
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "adopt_children_job.h"

#include <daemon.h>
#include <hydra.h>
#include <collections/array.h>

typedef struct private_adopt_children_job_t private_adopt_children_job_t;

/**
 * Private data of an adopt_children_job_t object.
 */
struct private_adopt_children_job_t {

	/**
	 * Public adopt_children_job_t interface.
	 */
	adopt_children_job_t public;

	/**
	 * IKE_SA id to adopt children from
	 */
	ike_sa_id_t *id;

	/**
	 * Tasks queued for execution
	 */
	array_t *tasks;
};

METHOD(job_t, destroy, void,
	private_adopt_children_job_t *this)
{
	array_destroy_offset(this->tasks, offsetof(task_t, destroy));
	this->id->destroy(this->id);
	free(this);
}

METHOD(job_t, execute, job_requeue_t,
	private_adopt_children_job_t *this)
{
	identification_t *my_id, *other_id, *xauth;
	host_t *me, *other, *vip;
	peer_cfg_t *cfg;
	linked_list_t *children, *vips;
	enumerator_t *enumerator, *subenum;
	ike_sa_id_t *id;
	ike_sa_t *new_sa, *old_sa;
	child_sa_t *child_sa;

	new_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager, this->id);
	if (new_sa)
	{
		/* get what we need from new SA */
		me = new_sa->get_my_host(new_sa);
		other = new_sa->get_other_host(new_sa);
		my_id = new_sa->get_my_id(new_sa);
		other_id = new_sa->get_other_id(new_sa);
		xauth = new_sa->get_other_eap_id(new_sa);
		cfg = new_sa->get_peer_cfg(new_sa);

		/* find old SA to adopt children and virtual IPs from */
		vips = linked_list_create();
		children = linked_list_create();
		enumerator = charon->ike_sa_manager->create_id_enumerator(
									charon->ike_sa_manager, my_id, xauth,
									other->get_family(other));
		while (enumerator->enumerate(enumerator, &id))
		{
			if (id->equals(id, this->id))
			{	/* not from self */
				continue;
			}
			old_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager, id);
			if (old_sa)
			{
				if ((old_sa->get_state(old_sa) == IKE_ESTABLISHED ||
					 old_sa->get_state(old_sa) == IKE_PASSIVE) &&
					me->equals(me, old_sa->get_my_host(old_sa)) &&
					other->equals(other, old_sa->get_other_host(old_sa)) &&
					other_id->equals(other_id, old_sa->get_other_id(old_sa)) &&
					cfg->equals(cfg, old_sa->get_peer_cfg(old_sa)))
				{
					subenum = old_sa->create_child_sa_enumerator(old_sa);
					while (subenum->enumerate(subenum, &child_sa))
					{
						old_sa->remove_child_sa(old_sa, subenum);
						children->insert_last(children, child_sa);
					}
					subenum->destroy(subenum);

					subenum = old_sa->create_virtual_ip_enumerator(old_sa, FALSE);
					while (subenum->enumerate(subenum, &vip))
					{
						vips->insert_last(vips, vip->clone(vip));
					}
					subenum->destroy(subenum);
					/* this does not release the addresses, which is good, but
					 * it does trigger an assign_vips(FALSE) event, so we also
					 * trigger one below */
					old_sa->clear_virtual_ips(old_sa, FALSE);
					if (children->get_count(children) || vips->get_count(vips))
					{
						DBG1(DBG_IKE, "detected reauth of existing IKE_SA, "
							 "adopting %d children and %d virtual IPs",
							 children->get_count(children), vips->get_count(vips));
					}
					old_sa->set_state(old_sa, IKE_DELETING);
					charon->bus->ike_updown(charon->bus, old_sa, FALSE);
					charon->ike_sa_manager->checkin_and_destroy(
											charon->ike_sa_manager, old_sa);
				}
				else
				{
					charon->ike_sa_manager->checkin(
											charon->ike_sa_manager, old_sa);
				}
				if (children->get_count(children) || vips->get_count(vips))
				{
					break;
				}
			}
		}
		enumerator->destroy(enumerator);

		while (children->remove_last(children, (void**)&child_sa) == SUCCESS)
		{
			new_sa->add_child_sa(new_sa, child_sa);
		}
		children->destroy(children);

		if (vips->get_count(vips))
		{
			while (vips->remove_first(vips, (void**)&vip) == SUCCESS)
			{
				new_sa->add_virtual_ip(new_sa, FALSE, vip);
				vip->destroy(vip);
			}
			charon->bus->assign_vips(charon->bus, new_sa, TRUE);
		}
		vips->destroy(vips);

		if (array_count(this->tasks))
		{
			task_t *task;

			while (array_remove(this->tasks, ARRAY_HEAD, &task))
			{
				task->migrate(task, new_sa);
				new_sa->queue_task(new_sa, task);
			}
			if (new_sa->initiate(new_sa, NULL, 0, NULL, NULL) == DESTROY_ME)
			{
				charon->ike_sa_manager->checkin_and_destroy(
												charon->ike_sa_manager, new_sa);
			}
			else
			{
				charon->ike_sa_manager->checkin(charon->ike_sa_manager,
												new_sa);
			}
		}
		else
		{
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, new_sa);
		}
	}
	return JOB_REQUEUE_NONE;
}

METHOD(job_t, get_priority, job_priority_t,
	private_adopt_children_job_t *this)
{
	return JOB_PRIO_HIGH;
}

METHOD(adopt_children_job_t, queue_task, void,
	private_adopt_children_job_t *this, task_t *task)
{
	array_insert_create(&this->tasks, ARRAY_TAIL, task);
}

/**
 * See header
 */
adopt_children_job_t *adopt_children_job_create(ike_sa_id_t *id)
{
	private_adopt_children_job_t *this;

	INIT(this,
		.public = {
			.job_interface = {
				.execute = _execute,
				.get_priority = _get_priority,
				.destroy = _destroy,
			},
			.queue_task = _queue_task,
		},
		.id = id->clone(id),
	);

	return &this->public;
}
