/* /src/entities/group_map.ts
  Let's map everything together. */

import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  UpdateDateColumn,
} from 'typeorm';

import { Group } from './group';
import { User } from './user';

import { GroupMemberPrivilege } from './../init/privilege';

@Entity()
@Index('user_group', ['user', 'group'])
export class GroupMap {

  @ManyToOne(() => Group, (group) => group.users, {
    primary: true,
    cascadeInsert: true,
    cascadeUpdate: true,
    cascadeRemove: true,
  })
  @JoinColumn()
  @Index()
  public group: Group;

  @ManyToOne(() => User, (user) => user.groups, {
    primary: true,
    cascadeInsert: true,
    cascadeUpdate: true,
    cascadeRemove: true,
  })
  @JoinColumn()
  @Index()
  public user: User;

  @Column('tinyint', {
    default: GroupMemberPrivilege.isMember || 0,
  })
  @Index()
  public privilege: number;

  @CreateDateColumn()
  public createdAt: string;

  @UpdateDateColumn()
  public updatedAt: string;
}
