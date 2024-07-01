/**
 * Script Name: updateDBSSPIRepo.groovy
 * Author: Jesus Nunez
 * Date: 2024-07-01
 * Description: This updates the value in an agent property for a specific set of agents
 * Usage: Run this groovy script in the Foglight Script Console
 * https://support.quest.com/kb/4309796/running-a-groovy-script-using-the-script-console
 * Update the set of agents in agentList
 * Update the SQL PI hostname in agentASPValue
 * Version History:
 *   - 1.0 (2024-07-01): Initial version
 */

srvConfig = server["ConfigService"];
srvAgent = server["AgentService"];

namespace = "DB_SQL_Server";
agentType = "DB_SQL_Server";
agentProperty = "parcStorageHost";
agentASPValue = "sqlserverhost";

def agentList = ["AGENT1","AGENT2", "AGENT3"]
def allAgents = srvAgent.findByAdapterAndType("FglAM", agentType);

allAgents.findAll{it.getName() in agentList}.each {agent ->
	primaryASP = srvConfig.getAgentInstancePrimaryAsp(namespace, agentType, agent.getId());
	primaryASP.setValueByString( agentProperty, agentASPValue);
	srvConfig.saveConfig(primaryASP);
	print("Updated ${agent.getName()} ${agentProperty} to ${agentASPValue}");
}

return "Check 'Log Messages' tab for details";
